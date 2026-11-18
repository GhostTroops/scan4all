package reader

import (
	"context"
	"errors"
	"io"
	"syscall"
	"time"

	"github.com/docker/go-units"
	contextutil "github.com/projectdiscovery/utils/context"
	"github.com/projectdiscovery/utils/errkit"
)

var (
	// although this is more than enough for most cases
	MaxReadSize, _ = units.FromHumanSize("8mb")
)

var (
	ErrTooLarge = errors.New("reader: too large only 8MB allowed as per MaxReadSize")
)

// ConnReadN reads at most N bytes from reader and it optimized
// for connection based readers like net.Conn it should not be used
// for file/buffer based reading, ConnReadN should be preferred
// instead of 'conn.Read() without loop' . It ignores EOF, UnexpectedEOF and timeout errors
// Note: you are responsible for adding a timeout to context
// Note: if the reader supports SetReadDeadline (e.g. net.Conn), a cancelled
// context expires its read deadline to unblock a pending read, leaving the
// deadline in the past; a connection whose read was cancelled should be
// discarded rather than reused.
func ConnReadN(ctx context.Context, reader io.Reader, N int64) ([]byte, error) {
	if N == -1 {
		N = MaxReadSize
	} else if N < -1 {
		return nil, errors.New("reader: N cannot be less than -1")
	} else if N == 0 {
		return []byte{}, nil
	} else if N > MaxReadSize {
		return nil, ErrTooLarge
	}
	var readErr error
	pr, pw := io.Pipe()

	// When using the Nuclei network protocol to read all available data from a connection,
	// there may be a timeout error after data has been sent by server. In this scenario,
	// we should return the data and ignore the error (if it is a timeout error).
	// To avoid race conditions, we use io.Pipe() along with a goroutine.
	// For an example of this scenario, refer to TestConnReadN#6.

	go func() {
		defer func() {
			_ = pw.Close()
		}()
		readDone := make(chan struct{})
		fn := func() (int64, error) {
			defer close(readDone)
			return io.CopyN(pw, io.LimitReader(reader, N), N)
		}
		// A context deadline can't interrupt a blocking Read. If the context wins
		// and the reader supports deadlines (net.Conn and friends), expire its read
		// deadline and wait for Read to return instead of leaking its goroutine.
		rd, canSetReadDeadline := reader.(interface{ SetReadDeadline(time.Time) error })
		_, readErr = contextutil.ExecFuncWithTwoReturns(ctx, fn)
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(readErr, ctxErr) && canSetReadDeadline {
			if err := rd.SetReadDeadline(time.Now()); err == nil {
				<-readDone
			}
		}
		// On cancellation report the context error rather than the net timeout
		// produced by expiring the deadline, so the timeout handling below is
		// deterministic instead of depending on which goroutine wins.
		if readErr != nil && ctx.Err() != nil {
			readErr = ctx.Err()
		}
	}()

	// read from pipe and return
	bin, err2 := io.ReadAll(pr)
	if err2 != nil {
		return nil, errkit.Wrapf(err2, "something went wrong while reading from pipe")
	}

	if readErr != nil {
		if errors.Is(readErr, context.DeadlineExceeded) && len(bin) > 0 {
			// if error is a timeout error and we have some data already
			// then return data and ignore error
			return bin, nil
		} else if IsAcceptedError(readErr) {
			// if error is accepted error ex: EOF, UnexpectedEOF, connection refused
			// then return data and ignore error
			return bin, nil
		} else {
			return nil, errkit.Wrap(readErr, "reader: error while reading from connection")
		}
	} else {
		return bin, nil
	}
}

// ConnReadNWithTimeout is same as ConnReadN but it takes timeout
// instead of context and it returns error if read does not finish in given time
func ConnReadNWithTimeout(reader io.Reader, N int64, after time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), after)
	defer cancel()
	return ConnReadN(ctx, reader, N)
}

// IsAcceptedError checks if the error is accepted error
// for example: connection refused, io.EOF, io.ErrUnexpectedEOF
// while reading from connection
func IsAcceptedError(err error) bool {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// ideally we should error out if we get a timeout error but
		// that's different for our use case
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return false
}
