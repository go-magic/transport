package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type transferWriter struct {
	Method           string
	Body             io.Reader
	BodyCloser       io.Closer
	ResponseToHEAD   bool
	ContentLength    int64 // -1 means unknown, 0 means exactly none
	Close            bool
	TransferEncoding []string
	Header           http.Header
	Trailer          http.Header
	IsResponse       bool
	bodyReadError    error // any non-EOF error from reading Body

	FlushHeaders bool            // flush headers to network before body
	ByteReadCh   chan readResult // non-nil if probeRequestBody called
}

type readResult struct {
	n   int
	err error
	b   byte // byte read, if n == 1
}

func requestMethodUsuallyLacksBody(method string) bool {
	switch method {
	case "GET", "HEAD", "DELETE", "OPTIONS", "PROPFIND", "SEARCH":
		return true
	}
	return false
}

type errorReader struct {
	err error
}

func (r errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

type byteReader struct {
	b    byte
	done bool
}

func (br *byteReader) Read(p []byte) (n int, err error) {
	if br.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	br.done = true
	p[0] = br.b
	return 1, io.EOF
}

func (t *transferWriter) probeRequestBody() {
	t.ByteReadCh = make(chan readResult, 1)
	go func(body io.Reader) {
		var buf [1]byte
		var rres readResult
		rres.n, rres.err = body.Read(buf[:])
		if rres.n == 1 {
			rres.b = buf[0]
		}
		t.ByteReadCh <- rres
	}(t.Body)
	timer := time.NewTimer(200 * time.Millisecond)
	select {
	case rres := <-t.ByteReadCh:
		timer.Stop()
		if rres.n == 0 && rres.err == io.EOF {
			// It was empty.
			t.Body = nil
			t.ContentLength = 0
		} else if rres.n == 1 {
			if rres.err != nil {
				t.Body = io.MultiReader(&byteReader{b: rres.b}, errorReader{rres.err})
			} else {
				t.Body = io.MultiReader(&byteReader{b: rres.b}, t.Body)
			}
		} else if rres.err != nil {
			t.Body = errorReader{rres.err}
		}
	case <-timer.C:
		// Too slow. Don't wait. Read it later, and keep
		// assuming that this is ContentLength == -1
		// (unknown), which means we'll send a
		// "Transfer-Encoding: chunked" header.
		t.Body = io.MultiReader(finishAsyncByteRead{t}, t.Body)
		// Request that Request.Write flush the headers to the
		// network before writing the body, since our body may not
		// become readable until it's seen the response headers.
		t.FlushHeaders = true
	}
}

type finishAsyncByteRead struct {
	tw *transferWriter
}

func (fr finishAsyncByteRead) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	rres := <-fr.tw.ByteReadCh
	n, err = rres.n, rres.err
	if n == 1 {
		p[0] = rres.b
	}
	return
}

func (t *transferWriter) shouldSendChunkedRequestBody() bool {
	// Note that t.ContentLength is the corrected content length
	// from rr.outgoingLength, so 0 actually means zero, not unknown.
	if t.ContentLength >= 0 || t.Body == nil { // redundant checks; caller did them
		return false
	}
	if t.Method == "CONNECT" {
		return false
	}
	if requestMethodUsuallyLacksBody(t.Method) {
		// Only probe the Request.Body for GET/HEAD/DELETE/etc
		// requests, because it's only those types of requests
		// that confuse servers.
		t.probeRequestBody() // adjusts t.Body, t.ContentLength
		return t.Body != nil
	}
	// For all other request types (PUT, POST, PATCH, or anything
	// made-up we've never heard of), assume it's normal and the interface
	// can deal with a chunked request body. Maybe we'll adjust this
	// later.
	return true
}

func newTransferWriter(r interface{}) (t *transferWriter, err error) {
	t = &transferWriter{}

	// Extract relevant fields
	atLeastHTTP11 := false
	switch rr := r.(type) {
	case *http.Request:
		if rr.ContentLength != 0 && rr.Body == nil {
			return nil, fmt.Errorf("http: Request.ContentLength=%d with nil Body", rr.ContentLength)
		}
		t.Method = valueOrDefault(rr.Method, "GET")
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Header = rr.Header
		t.Trailer = rr.Trailer
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = outgoingLength(rr)
		if t.ContentLength < 0 && len(t.TransferEncoding) == 0 && t.shouldSendChunkedRequestBody() {
			t.TransferEncoding = []string{"chunked"}
		}
		// If there's a body, conservatively flush the headers
		// to any bufio.Writer we're writing to, just in case
		// the interface needs the headers early, before we copy
		// the body and possibly block. We make an exception
		// for the common standard library in-memory types,
		// though, to avoid unnecessary TCP packets on the
		// wire. (Issue 22088.)
		if t.ContentLength != 0 && !isKnownInMemoryReader(t.Body) {
			t.FlushHeaders = true
		}

		atLeastHTTP11 = true // Transport requests are always 1.1 or 2.0
	case *http.Response:
		t.IsResponse = true
		if rr.Request != nil {
			t.Method = rr.Request.Method
		}
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.ContentLength
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Header = rr.Header
		t.Trailer = rr.Trailer
		atLeastHTTP11 = rr.ProtoAtLeast(1, 1)
		t.ResponseToHEAD = noResponseBodyExpected(t.Method)
	}

	// Sanitize Body,ContentLength,TransferEncoding
	if t.ResponseToHEAD {
		t.Body = nil
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		}
	} else {
		if !atLeastHTTP11 || t.Body == nil {
			t.TransferEncoding = nil
		}
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		} else if t.Body == nil { // no chunking, no body
			t.ContentLength = 0
		}
	}

	// Sanitize Trailer
	if !chunked(t.TransferEncoding) {
		t.Trailer = nil
	}

	return t, nil
}

func chunked(te []string) bool { return len(te) > 0 && te[0] == "chunked" }

func noResponseBodyExpected(requestMethod string) bool {
	return requestMethod == "HEAD"
}

func isKnownInMemoryReader(r io.Reader) bool {
	switch r.(type) {
	case *bytes.Reader, *bytes.Buffer, *strings.Reader:
		return true
	}
	if reflect.TypeOf(r) == nopCloserType {
		return isKnownInMemoryReader(reflect.ValueOf(r).Field(0).Interface().(io.Reader))
	}
	return false
}

var nopCloserType = reflect.TypeOf(ioutil.NopCloser(nil))

func (t *transferWriter) writeHeader(w io.Writer, trace *httptrace.ClientTrace) error {
	if t.Close && !hasToken(headerGet(t.Header, "Connection"), "close") {
		if _, err := io.WriteString(w, "Connection: close\r\n"); err != nil {
			return err
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField("Connection", []string{"close"})
		}
	}

	// Write Content-Length and/or Transfer-Encoding whose values are a
	// function of the sanitized field triple (Body, ContentLength,
	// TransferEncoding)
	if t.shouldSendContentLength() {
		if _, err := io.WriteString(w, "Content-Length: "); err != nil {
			return err
		}
		if _, err := io.WriteString(w, strconv.FormatInt(t.ContentLength, 10)+"\r\n"); err != nil {
			return err
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField("Content-Length", []string{strconv.FormatInt(t.ContentLength, 10)})
		}
	} else if chunked(t.TransferEncoding) {
		if _, err := io.WriteString(w, "Transfer-Encoding: chunked\r\n"); err != nil {
			return err
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField("Transfer-Encoding", []string{"chunked"})
		}
	}

	// Write Trailer header
	if t.Trailer != nil {
		keys := make([]string, 0, len(t.Trailer))
		for k := range t.Trailer {
			k = CanonicalHeaderKey(k)
			switch k {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				return &badStringError{"invalid Trailer key", k}
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			sort.Strings(keys)
			// TODO: could do better allocation-wise here, but trailers are rare,
			// so being lazy for now.
			if _, err := io.WriteString(w, "Trailer: "+strings.Join(keys, ",")+"\r\n"); err != nil {
				return err
			}
			if trace != nil && trace.WroteHeaderField != nil {
				trace.WroteHeaderField("Trailer", keys)
			}
		}
	}

	return nil
}

func CanonicalHeaderKey(s string) string { return textproto.CanonicalMIMEHeaderKey(s) }

func (t *transferWriter) shouldSendContentLength() bool {
	if chunked(t.TransferEncoding) {
		return false
	}
	if t.ContentLength > 0 {
		return true
	}
	if t.ContentLength < 0 {
		return false
	}
	// Many servers expect a Content-Length for these methods
	if t.Method == "POST" || t.Method == "PUT" {
		return true
	}
	if t.ContentLength == 0 && isIdentity(t.TransferEncoding) {
		if t.Method == "GET" || t.Method == "HEAD" {
			return false
		}
		return true
	}

	return false
}

func isIdentity(te []string) bool { return len(te) == 1 && te[0] == "identity" }

func (t *transferWriter) unwrapBody() io.Reader {
	if reflect.TypeOf(t.Body) == nopCloserType {
		return reflect.ValueOf(t.Body).Field(0).Interface().(io.Reader)
	}

	return t.Body
}

type bufioFlushWriter struct{ w io.Writer }

func (fw bufioFlushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if bw, ok := fw.w.(*bufio.Writer); n > 0 && ok {
		ferr := bw.Flush()
		if ferr != nil && err == nil {
			err = ferr
		}
	}
	return
}

func (t *transferWriter) writeBody(w io.Writer) error {
	var err error
	var ncopy int64

	// Write body. We "unwrap" the body first if it was wrapped in a
	// nopCloser. This is to ensure that we can take advantage of
	// OS-level optimizations in the event that the body is an
	// *os.File.
	if t.Body != nil {
		var body = t.unwrapBody()
		if chunked(t.TransferEncoding) {
			if bw, ok := w.(*bufio.Writer); ok && !t.IsResponse {
				w = &FlushAfterChunkWriter{Writer: bw}
			}
			cw := NewChunkedWriter(w)
			_, err = t.doBodyCopy(cw, body)
			if err == nil {
				err = cw.Close()
			}
		} else if t.ContentLength == -1 {
			dst := w
			if t.Method == "CONNECT" {
				dst = bufioFlushWriter{dst}
			}
			ncopy, err = t.doBodyCopy(dst, body)
		} else {
			ncopy, err = t.doBodyCopy(w, io.LimitReader(body, t.ContentLength))
			if err != nil {
				return err
			}
			var nextra int64
			nextra, err = t.doBodyCopy(ioutil.Discard, body)
			ncopy += nextra
		}
		if err != nil {
			return err
		}
	}
	if t.BodyCloser != nil {
		if err := t.BodyCloser.Close(); err != nil {
			return err
		}
	}

	if !t.ResponseToHEAD && t.ContentLength != -1 && t.ContentLength != ncopy {
		return fmt.Errorf("http: ContentLength=%d with Body length %d",
			t.ContentLength, ncopy)
	}

	if chunked(t.TransferEncoding) {
		// Write Trailer header
		if t.Trailer != nil {
			if err := t.Trailer.Write(w); err != nil {
				return err
			}
		}
		// Last chunk, empty trailer
		_, err = io.WriteString(w, "\r\n")
	}
	return err
}

func (t *transferWriter) doBodyCopy(dst io.Writer, src io.Reader) (n int64, err error) {
	n, err = io.Copy(dst, src)
	if err != nil && err != io.EOF {
		t.bodyReadError = err
	}
	return
}

type FlushAfterChunkWriter struct {
	*bufio.Writer
}

func NewChunkedWriter(w io.Writer) io.WriteCloser {
	return &chunkedWriter{w}
}

type chunkedWriter struct {
	Wire io.Writer
}

func (cw *chunkedWriter) Write(data []byte) (n int, err error) {

	// Don't send 0-length data. It looks like EOF for chunked encoding.
	if len(data) == 0 {
		return 0, nil
	}

	if _, err = fmt.Fprintf(cw.Wire, "%x\r\n", len(data)); err != nil {
		return 0, err
	}
	if n, err = cw.Wire.Write(data); err != nil {
		return
	}
	if n != len(data) {
		err = io.ErrShortWrite
		return
	}
	if _, err = io.WriteString(cw.Wire, "\r\n"); err != nil {
		return
	}
	if bw, ok := cw.Wire.(*FlushAfterChunkWriter); ok {
		err = bw.Flush()
	}
	return
}

func (cw *chunkedWriter) Close() error {
	_, err := io.WriteString(cw.Wire, "0\r\n")
	return err
}
