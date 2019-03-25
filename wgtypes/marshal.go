// Package wgtypes provides shared types for the wireguardctrl family
// of packages.
package wgtypes

import (
	"bytes"
	"encoding/base64"
	"text/template"
)

// TODO: Add tests

const wgtypeTemplateSpec =
	`[Interface]
{{- range := .Address }}
Address = {{ . }}
{{ end }}
{{- range := .DNS }}
DNS = {{ . }}
{{ end }}
PrivateKey = {{ .PrivateKey | wgKey }}
{{- if .ListenPort }}{{ "\n" }}ListenPort = {{ .ListenPort }}{{ end }}
{{- if .MTU }}{{ "\n" }}MTU = {{ .MTU }}{{ end }}
{{- if .Table }}{{ "\n" }}Table = {{ .Table }}{{ end }}
{{- if .PreUp }}{{ "\n" }}PreUp = {{ .PreUp }}{{ end }}
{{- if .PostUp }}{{ "\n" }}Table = {{ .Table }}{{ end }}
{{- if .PreDown }}{{ "\n" }}PreDown = {{ .PreDown }}{{ end }}
{{- if .PostDown }}{{ "\n" }}PostDown = {{ .PostDown }}{{ end }}
{{- if .SaveConfig }}{{ "\n" }}SaveConfig = {{ .SaveConfig }}{{ end }}
{{- range .Peers }}

[Peer]
PublicKey = {{ .PublicKey | wgKey }}
AllowedIps = {{ range $i, $el := .AllowedIPs }}{{if $i}}, {{ end }}{{ $el }}{{ end }}
{{- if .Endpoint }}{{ "\n" }}Endpoint = {{ .Endpoint }}{{ end }}

{{- end }}
`

func serializeKey(key *Key) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

var cfgTemplate = template.Must(
	template.
		New("wg-cfg").
		Funcs(template.FuncMap(map[string]interface{}{"wgKey": serializeKey})).
		Parse(wgtypeTemplateSpec))

func (cfg *Config)MarshalText() (text []byte, err error){
	buff := &bytes.Buffer{}
	if err := cfgTemplate.Execute(buff, cfg); err != nil {
		return nil, err
	}
	return buff.Bytes(), nil
}
