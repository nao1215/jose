package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func writeJSON(w io.Writer, v interface{}) error {
	buf, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSerializeJOSN, err.Error())
	}
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("%w: %s", ErrWriteJSON, err.Error())
	}
	return nil
}

func openOutputFile(path string) (io.WriteCloser, error) {
	var output io.WriteCloser
	switch path {
	case "-":
		output = os.Stdout
	default:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf(`%w: %s`, ErrCreateFile, err.Error())
		}
		output = f
	}
	return output, nil
}

func availableCurves() []string {
	curves := []string{}
	for _, v := range jwk.AvailableCurves() {
		curves = append(curves, v.Params().Name)
	}

	return curves
}
