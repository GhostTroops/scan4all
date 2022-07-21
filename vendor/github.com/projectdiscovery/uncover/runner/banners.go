package runner

import (
	"github.com/projectdiscovery/gologger"
)

const banner = `
  __  ______  _________ _   _____  _____
 / / / / __ \/ ___/ __ \ | / / _ \/ ___/
/ /_/ / / / / /__/ /_/ / |/ /  __/ /    
\__,_/_/ /_/\___/\____/|___/\___/_/ v0.0.5
`

// Version is the current version of uncover
const Version = `v0.0.5`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
	gologger.Print().Msgf("By using uncover, you also agree to the terms of the APIs used.\n\n")
}
