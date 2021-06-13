package streams

import "io"

func WriteAllBytes(dest io.Writer, src []byte) error {
	currRead := 0
	for {
		n, err := dest.Write(src[currRead:])
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// If no errors, but nothing was read we can assume EOF:
		if n == 0 {
			break
		}

		currRead += n
	}

	return nil
}