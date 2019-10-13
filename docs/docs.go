// GENERATED BY THE COMMAND ABOVE; DO NOT EDIT
// This file was generated by swaggo/swag at
// 2019-10-13 13:23:08.783625716 +0200 CEST m=+0.042293197

package docs

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/alecthomas/template"
	"github.com/swaggo/swag"
)

var doc = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{.Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "license": {
            "name": "Apache 2.0",
            "url": "https://github.com/bihe/login-go/blob/master/LICENSE"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/v1/appinfo": {
            "get": {
                "description": "meta-data of the application including authenticated user and version",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "appinfo"
                ],
                "summary": "provides information about the application",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/appinfo.Meta"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    }
                }
            }
        },
        "/api/v1/sites": {
            "get": {
                "description": "returns all the sites of the current loged-in user",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "sites"
                ],
                "summary": "sites of current user",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/sites.UserInfo"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    }
                }
            },
            "post": {
                "description": "takes a list of sites and stores the supplied sites for the user",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "sites"
                ],
                "summary": "stores the given sites",
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/core.ProblemDetail"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "appinfo.Meta": {
            "type": "object",
            "properties": {
                "displayName": {
                    "type": "string"
                },
                "email": {
                    "type": "string"
                },
                "roles": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "runtime": {
                    "type": "string"
                },
                "version": {
                    "type": "string"
                }
            }
        },
        "core.ProblemDetail": {
            "type": "object",
            "properties": {
                "detail": {
                    "description": "Detail is a human-readable explanation specific to this occurrence of the problem",
                    "type": "string"
                },
                "instance": {
                    "description": "Instance is a URI reference that identifies the specific occurrence of the problem",
                    "type": "string"
                },
                "status": {
                    "description": "Status is the HTTP status code",
                    "type": "integer"
                },
                "title": {
                    "description": "Title is a short, human-readable summary of the problem type",
                    "type": "string"
                },
                "type": {
                    "description": "Type is a URI reference [RFC3986] that identifies the\nproblem type.  This specification encourages that, when\ndereferenced, it provide human-readable documentation for the problem",
                    "type": "string"
                }
            }
        },
        "sites.SiteInfo": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "permissions": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "url": {
                    "type": "string"
                }
            }
        },
        "sites.UserInfo": {
            "type": "object",
            "properties": {
                "editable": {
                    "type": "boolean"
                },
                "user": {
                    "type": "string"
                },
                "userSites": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/sites.SiteInfo"
                    }
                }
            }
        }
    }
}`

type swaggerInfo struct {
	Version     string
	Host        string
	BasePath    string
	Schemes     []string
	Title       string
	Description string
}

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = swaggerInfo{
	Version:     "2.0",
	Host:        "",
	BasePath:    "",
	Schemes:     []string{},
	Title:       "login application",
	Description: "The central login for all my applications",
}

type s struct{}

func (s *s) ReadDoc() string {
	sInfo := SwaggerInfo
	sInfo.Description = strings.Replace(sInfo.Description, "\n", "\\n", -1)

	t, err := template.New("swagger_info").Funcs(template.FuncMap{
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
	}).Parse(doc)
	if err != nil {
		return doc
	}

	var tpl bytes.Buffer
	if err := t.Execute(&tpl, sInfo); err != nil {
		return doc
	}

	return tpl.String()
}

func init() {
	swag.Register(swag.Name, &s{})
}
