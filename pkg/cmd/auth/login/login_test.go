package login

import (
	"bytes"
	"testing"

	"github.com/cli/cli/pkg/cmdutil"
	"github.com/cli/cli/pkg/iostreams"
	"github.com/google/shlex"
	"github.com/stretchr/testify/assert"
)

func Test_NewCmdLogin(t *testing.T) {
	tests := []struct {
		name     string
		cli      string
		wants    LoginOptions
		wantsErr bool
	}{
		{
			name: "pat",
			cli:  "--pat abc123",
			wants: LoginOptions{
				PAT: "abc123",
			},
		},
		{
			name: "no pat",
			cli:  "",
			wants: LoginOptions{
				PAT: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			io, _, _, _ := iostreams.Test()
			f := &cmdutil.Factory{
				IOStreams: io,
			}

			argv, err := shlex.Split(tt.cli)
			assert.NoError(t, err)

			var gotOpts *LoginOptions
			cmd := NewCmdLogin(f, func(opts *LoginOptions) error {
				gotOpts = opts
				return nil
			})

			cmd.SetArgs(argv)
			cmd.SetIn(&bytes.Buffer{})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})

			_, err = cmd.ExecuteC()
			if tt.wantsErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, tt.wants.PAT, gotOpts.PAT)
		})
	}
}

func Test_loginRun(t *testing.T) {
	tests := []struct {
		name       string
		opts       *LoginOptions
		tty        bool
		wantStdout string
		wantStderr string
		wantErr    bool
	}{
		{
			name:    "non-tty error",
			tty:     false,
			opts:    &LoginOptions{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		io, _, stdout, stderr := iostreams.Test()

		io.SetStdinTTY(tt.tty)
		io.SetStdoutTTY(tt.tty)

		tt.opts.IO = io
		t.Run(tt.name, func(t *testing.T) {
			if err := loginRun(tt.opts); (err != nil) != tt.wantErr {
				t.Errorf("loginRun() error = %v, wantErr %v", err, tt.wantErr)
			}

			assert.Equal(t, tt.wantStdout, stdout.String())
			assert.Equal(t, tt.wantStderr, stderr.String())
		})
	}
}

func Test_loginRun_ConfiguresProtocol(t *testing.T) {
	io, _, _, _ := iostreams.Test()

	reg := &httpmock.Registry{}
	opts := &LoginOptions{
		IO: io,
		HttpClient: func() (*http.Client, error) {
			return &http.Client{Transport: reg}, nil
		},
	}
	cmd := NewCmdLogin()

}
