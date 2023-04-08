package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/spf13/cobra"
)

func newJWSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jws",
		Short: "Work with JWS messages",
	}

	cmd.AddCommand(newJWSParseCmd())
	return cmd
}

func newJWSParseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse",
		Short: "Parse JWS mesage",
		Long: ` Parse FILE and display information about a JWS message.
Use "-" as FILE to read from STDIN.`,
		RunE: runJWSParse,
	}
	return cmd
}

type jwsParser struct {
	InputFilePath string `validate:"-"`
}

func newJWSParser(args []string) (*jwsParser, error) {
	inputFilePath := ""
	if len(args) != 0 {
		inputFilePath = args[0]
	}

	return &jwsParser{
		InputFilePath: inputFilePath,
	}, nil
}

func runJWSParse(_ *cobra.Command, args []string) error {
	jwsParser, err := newJWSParser(args)
	if err != nil {
		return err
	}

	src, err := openInputFile(jwsParser.InputFilePath)
	if err != nil {
		return err
	}
	defer func() {
		if e := src.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()

	buf, err := io.ReadAll(src)
	if err != nil {
		return wrap(ErrReadFile, err.Error())
	}

	msg, err := jws.Parse(buf)
	if err != nil {
		return wrap(ErrParseMessage, err.Error())
	}

	if err := writeJSON(os.Stdout, msg); err != nil {
		return err
	}

	for i, sig := range msg.Signatures() {
		fmt.Fprintf(os.Stdout, "Signature %d: ", i)
		if err := writeJSON(os.Stdout, sig.ProtectedHeaders()); err != nil {
			return err
		}
	}
	return nil
}
