package login

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/api"
	"github.com/cli/cli/internal/config"
	"github.com/cli/cli/pkg/cmdutil"
	"github.com/cli/cli/pkg/iostreams"
	"github.com/cli/cli/pkg/prompt"
	"github.com/cli/cli/utils"
	"github.com/spf13/cobra"
)

type LoginOptions struct {
	HttpClient func() (*http.Client, error)
	IO         *iostreams.IOStreams
	Config     func() (config.Config, error)

	PAT string
}

func NewCmdLogin(f *cmdutil.Factory, runF func(*LoginOptions) error) *cobra.Command {
	opts := &LoginOptions{
		HttpClient: f.HttpClient,
		IO:         f.IOStreams,
		Config:     f.Config,
	}

	cmd := &cobra.Command{
		Use:   "login",
		Args:  cobra.ExactArgs(0),
		Short: "Authenticate with a GitHub host",
		Long: heredoc.Doc(`Authenticate with a GitHub host.

			This interactive command initializes your authentication state either by helping you log into
			GitHub via browser-based OAuth or by accepting a Personal Access Token.

			The interactivity can be avoided by passing a personal access token with --pat.
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return loginRun(opts)
		},
	}

	cmd.Flags().StringVar(&opts.PAT, "pat", "", "a Personal Access Token.")

	return cmd
}

func loginRun(opts *LoginOptions) error {
	cfg, err := opts.Config()
	if err != nil {
		return err
	}

	if opts.PAT != "" {
		// TODO
		// Right now we support PAT via GITHUB_TOKEN and as far as we can tell do not persist it. I'm
		// thinking authenticating in this way would add a pat: section to the hosts.yml but I want to
		// clarify that with mislav.
		return nil
	}

	isTTY := opts.IO.IsStdoutTTY() && opts.IO.IsStdinTTY()

	if !isTTY {
		return errors.New("--pat required when unattached to terminal")
	}

	// TODO consider explicitly telling survey what io to use since it's implicit right now

	var hostType int
	err = prompt.SurveyAskOne(&survey.Select{
		Message: "What account do you want to log into?",
		Options: []string{
			"GitHub.com",
			"GitHub Enterprise",
		},
	}, &hostType)

	if err != nil {
		return fmt.Errorf("could not prompt: %w", err)
	}

	isEnterprise := hostType == 1

	// TODO use default hostname from mislav's work
	hostname := "github.com"
	if isEnterprise {
		err := prompt.SurveyAskOne(&survey.Input{
			Message: "GHE hostname:",
		}, &hostname, survey.WithValidator(survey.Required))
		if err != nil {
			return fmt.Errorf("could not prompt: %w", err)
		}
	}

	fmt.Fprintf(opts.IO.ErrOut, "- Logging into %s\n", hostname)

	var authMode int
	err = prompt.SurveyAskOne(&survey.Select{
		Message: "How would you like to authenticate?",
		Options: []string{
			"With a web browser (OAuth)",
			"Without a web browser (Personal Access Token)",
		},
	}, &authMode)
	if err != nil {
		return fmt.Errorf("could not prompt: %w", err)
	}

	if authMode == 0 {
		_, err := config.AuthFlowWithConfig(cfg, hostname, "")
		if err != nil {
			return fmt.Errorf("failed to authenticate via web browser: %w", err)
		}
	} else {
		var pat string
		err := prompt.SurveyAskOne(&survey.Input{
			Message: "Enter a Personal Access Token:",
		}, &pat, survey.WithValidator(survey.Required))

		if err != nil {
			return fmt.Errorf("could not prompt: %w", err)
		}

		// TODO do something with pat

	}

	var gitProtocol string
	err = prompt.SurveyAskOne(&survey.Select{
		Message: "Choose default git protocol",
		Options: []string{
			"HTTPS",
			"SSH",
		},
	}, &gitProtocol)

	gitProtocol = strings.ToLower(gitProtocol)

	fmt.Fprintf(opts.IO.ErrOut, "- gh config set -h%s git_protocol %s\n", hostname, gitProtocol)
	err = cfg.Set(hostname, "git_protocol", gitProtocol)
	if err != nil {
		return err
	}

	err = cfg.Write()
	if err != nil {
		return err
	}

	greenCheck := utils.Green("✓")
	fmt.Fprintf(opts.IO.ErrOut, "%s Configured git protocol\n", greenCheck)

	httpClient, err := opts.HttpClient()
	if err != nil {
		return err
	}

	apiClient := api.NewClientFromHTTP(httpClient)

	username, err := api.CurrentLoginName(apiClient)
	if err != nil {
		return fmt.Errorf("error using api: %w", err)
	}

	fmt.Fprintf(opts.IO.ErrOut, "%s Logged in as %s\n", greenCheck, utils.Bold(username))

	return nil
}
