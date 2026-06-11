package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/client"
)

func newStatusCommand(o *opts) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show chain id, latest height and app hash of the node",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client.New(o.node)
			if err != nil {
				return err
			}
			st, err := c.Status(cmd.Context())
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Node:          %s\n", c.Remote())
			fmt.Fprintf(out, "Chain ID:      %s\n", st.NodeInfo.Network)
			fmt.Fprintf(out, "Latest height: %d\n", st.SyncInfo.LatestBlockHeight)
			fmt.Fprintf(out, "App hash:      %X\n", st.SyncInfo.LatestAppHash)
			fmt.Fprintf(out, "Catching up:   %v\n", st.SyncInfo.CatchingUp)
			return nil
		},
	}
}
