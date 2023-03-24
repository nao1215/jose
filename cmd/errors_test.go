package cmd

import (
	"errors"
	"testing"
)

func TestWrap(t *testing.T) {
	type args struct {
		e   error
		msg string
	}
	tests := []struct {
		name       string
		args       args
		wantErrMsg string
	}{
		{
			name: "wrap error message",
			args: args{
				e:   errors.New("new error"),
				msg: "message",
			},
			wantErrMsg: "new error: message",
		},
		{
			name: "make new error because user not specify nil for error",
			args: args{
				e:   nil,
				msg: "make new error",
			},
			wantErrMsg: "make new error",
		},
		{
			name: "Return error(e) as it is",
			args: args{
				e:   errors.New("this is return value"),
				msg: "",
			},
			wantErrMsg: "this is return value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrap(tt.args.e, tt.args.msg)
			if got == nil {
				t.Fatal("expect return error, however errfmt.Wrap() return nil")
			}
			if got.Error() != tt.wantErrMsg {
				t.Errorf("want=%s, got=%s", tt.wantErrMsg, got.Error())
			}
		})
	}
}
