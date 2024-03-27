package data

type AttestationPayload struct {
	Type          string    `json:"_type"`
	PredicateType string    `json:"predicateType"`
	Subject       []Subject `json:"subject"`
	Predicate     Predicate `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Predicate struct {
	Invocation Invocation `json:"invocation"`
	Scanner    Scanner    `json:"scanner"`
}

type Invocation struct {
	Parameters []string `json:"parameters"`
	URI        string   `json:"uri"`
	EventID    string   `json:"event_id"`
	BuilderID  string   `json:"builder.id"`
}

type Scanner struct {
	URI     string   `json:"uri"`
	Version string   `json:"version"`
	DB      Database `json:"db"`
	Result  Result   `json:"result"`
}

type Database struct {
	URI     string `json:"uri"`
	Version string `json:"version"`
}

type Result struct {
	ArtifactName  string       `json:"ArtifactName"`
	ArtifactType  string       `json:"ArtifactType"`
	CreatedAt     string       `json:"CreatedAt"`
	Metadata      Metadata     `json:"Metadata"`
	Results       []ScanResult `json:"Results"`
	SchemaVersion int          `json:"SchemaVersion"`
}

type Metadata struct {
	DiffIDs     []string    `json:"DiffIDs"`
	ImageConfig ImageConfig `json:"ImageConfig"`
	ImageID     string      `json:"ImageID"`
	OS          OSInfo      `json:"OS"`
	RepoDigests []string    `json:"RepoDigests"`
	RepoTags    []string    `json:"RepoTags"`
}

type ImageConfig struct {
	Architecture  string    `json:"architecture"`
	Config        Config    `json:"config"`
	Container     string    `json:"container"`
	Created       string    `json:"created"`
	DockerVersion string    `json:"docker_version"`
	History       []History `json:"history"`
	OS            string    `json:"os"`
	Rootfs        Rootfs    `json:"rootfs"`
}

type Config struct {
	Cmd   []string `json:"Cmd"`
	Env   []string `json:"Env"`
	Image string   `json:"Image"`
}

type History struct {
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer,omitempty"` // Use omitempty since this field might not be present in all history entries
}

type Rootfs struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type OSInfo struct {
	EOSL   bool   `json:"EOSL"`
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	Severity         string   `json:"Severity"`
	Description      string   `json:"Description"`
	FixedVersion     string   `json:"FixedVersion"`
	InstalledVersion string   `json:"InstalledVersion"`
	PkgName          string   `json:"PkgName"`
	Title            string   `json:"Title"`
	PrimaryURL       string   `json:"PrimaryURL"`
	PublishedDate    string   `json:"PublishedDate"`
	LastModifiedDate string   `json:"LastModifiedDate"`
	References       []string `json:"References"`
	CVSS             CVSS     `json:"CVSS"`
}

type CVSS struct {
	Nvd    NvdCVSS    `json:"nvd"`
	Redhat RedhatCVSS `json:"redhat"`
}

type NvdCVSS struct {
	V2Vector string  `json:"V2Vector"`
	V2Score  float64 `json:"V2Score"`
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}

type RedhatCVSS struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}

type ScanResult struct {
	Class           string          `json:"Class"`
	Target          string          `json:"Target"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}
