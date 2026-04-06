package grc

// Control represents a GRC compliance control from any framework.
type Control struct {
	Framework              string      `json:"Framework"`
	ControlID              string      `json:"ControlID"`
	Title                  string      `json:"Title"`
	Family                 string      `json:"Family,omitempty"`
	Description            string      `json:"Description,omitempty"`
	Level                  string      `json:"Level,omitempty"`
	RelatedCWEs            []string    `json:"RelatedCWEs,omitempty"`
	RelatedCVEs            []string    `json:"RelatedCVEs,omitempty"`
	References             []Reference `json:"References,omitempty"`
	ImplementationGuidance string      `json:"ImplementationGuidance,omitempty"`
	AssessmentMethods      []string    `json:"AssessmentMethods,omitempty"`
}

// Reference is an external citation or documentation link for a control.
type Reference struct {
	Source  string `json:"source,omitempty"`
	URL     string `json:"url,omitempty"`
	Section string `json:"section,omitempty"`
}
