package main

type AzureErrorResponseDto struct {
	Code string `xml:"Body>Fault>Detail>error>internalerror>text"`
}
