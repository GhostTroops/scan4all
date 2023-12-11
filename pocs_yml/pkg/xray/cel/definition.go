package cel

import (
	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/structs"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	StrStrMapType = decls.NewMapType(decls.String, decls.String)
	RequestType   = decls.NewObjectType("structs.Request")
	ResponseType  = decls.NewObjectType("structs.Response")
	ReverseType   = decls.NewObjectType("structs.Reverse")
	UrlTypeType   = decls.NewObjectType("structs.UrlType")

	StandradEnvOptions = []cel.EnvOption{
		cel.Container("structs"),
		cel.Types(
			&structs.UrlType{},
			&structs.Request{},
			&structs.Response{},
			&structs.Reverse{},
			StrStrMapType,
		),
		cel.Declarations(
			decls.NewVar("request", RequestType),
			decls.NewVar("response", ResponseType),
		),
		cel.Declarations(
			// functions
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("ibcontains",
				decls.NewInstanceOverload("bytes_ibcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("icontains",
				decls.NewInstanceOverload("icontains_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("bstartsWith",
				decls.NewInstanceOverload("bytes_bstartsWith_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("submatch",
				decls.NewInstanceOverload("string_submatch_string",
					[]*exprpb.Type{decls.String, decls.String},
					StrStrMapType,
				)),
			decls.NewFunction("bmatches",
				decls.NewInstanceOverload("string_bmatches_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("bsubmatch",
				decls.NewInstanceOverload("string_bsubmatch_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					StrStrMapType,
				)),
			decls.NewFunction("wait",
				decls.NewInstanceOverload("reverse_wait_int",
					[]*exprpb.Type{decls.Any, decls.Int},
					decls.Bool)),
			decls.NewFunction("newReverse",
				decls.NewOverload("newReverse",
					[]*exprpb.Type{},
					ReverseType)),
			decls.NewFunction("md5",
				decls.NewOverload("md5_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("randomInt",
				decls.NewOverload("randomInt_int_int",
					[]*exprpb.Type{decls.Int, decls.Int},
					decls.Int)),
			decls.NewFunction("randomLowercase",
				decls.NewOverload("randomLowercase_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("substr",
				decls.NewOverload("substr_string_int_int",
					[]*exprpb.Type{decls.String, decls.Int, decls.Int},
					decls.String)),
			decls.NewFunction("replaceAll",
				decls.NewOverload("replaceAll_string_string_string",
					[]*exprpb.Type{decls.String, decls.String, decls.String},
					decls.String)),
			decls.NewFunction("printable",
				decls.NewOverload("printable_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("sleep",
				decls.NewOverload("sleep_int",
					[]*exprpb.Type{decls.Int},
					decls.Bool)),
			decls.NewFunction("faviconHash",
				decls.NewOverload("faviconHash_stringOrBytes",
					[]*exprpb.Type{decls.Any},
					decls.Int)),
			decls.NewFunction("toUintString",
				decls.NewOverload("toUintString_string_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.String)),
		),
	}
)

func NewFunctionDefineOptions(reg ref.TypeRegistry) []cel.EnvOption {

	newOptions := []cel.EnvOption{
		cel.CustomTypeAdapter(reg),
		cel.CustomTypeProvider(reg),
	}
	newOptions = append(newOptions, StandradEnvOptions...)

	return newOptions
}
