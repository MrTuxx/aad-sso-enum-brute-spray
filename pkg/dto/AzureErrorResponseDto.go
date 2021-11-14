package dto

type AzureErrorResponseDto struct {
	Error string `xml:"Body>Fault>Detail>error>internalerror>text"`
}
