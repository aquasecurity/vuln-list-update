package safetydb

import (
	"encoding/json"
)

type AdvisoryDB map[string][]RawAdvisory

type RawAdvisory struct {
	ID       string   `json:"id"`
	Advisory string   `json:"advisory"`
	Cve      string   `json:"cve"`
	Specs    []string `json:"specs"`
	Version  string   `json:"v"`
}

func (ad AdvisoryDB) UnmarshalJSON(data []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		panic(err)
	}
	for k, v := range obj {
		if k == "$meta" {
			continue
		}
		var raw []RawAdvisory
		if err := json.Unmarshal(v, &raw); err != nil {
			panic(err)
		}
		ad[k] = raw
	}
	return nil
}
