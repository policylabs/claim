// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package cmd implements the claim command line.
package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	version  = "devel"
	logLevel string
)

// Execute runs the root command.
func Execute() {
	root := &cobra.Command{
		Use:   "claim",
		Short: "distributed authorization for path-based resources",
		Long: `claim decides whether a pull request may change the paths it touches.

The repository receiving the change configures, per path, the AMPEL policy
that gates it and how to find the URL that owns the path. The owner publishes
a document with the context values the policy leaves open (for example the
identities allowed to sign commits under the path). claim fetches it, hands
the values to AMPEL and evaluates the policy against the head commit of the
pull request. The change is allowed only when every owned path passes.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			lvl, err := logrus.ParseLevel(logLevel)
			if err != nil {
				return fmt.Errorf("invalid log level %q: %w", logLevel, err)
			}
			logrus.SetLevel(lvl)
			logrus.SetOutput(os.Stderr)
			return nil
		},
	}
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	root.AddCommand(newCheckCommand(), newVersionCommand())
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print the claim version",
		Run: func(cmd *cobra.Command, _ []string) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), version) //nolint:errcheck // best-effort console output
		},
	}
}
