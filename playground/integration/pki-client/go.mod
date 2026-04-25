module pki-client

go 1.25.1

require github.com/tidwall/gjson v1.18.0

require (
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	local/merkle-trees v0.0.0
)

replace local/merkle-trees => ../../merkle-trees
