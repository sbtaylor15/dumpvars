# ortelius-ms-dep-pkg-cud

![Release](https://img.shields.io/github/v/release/ortelius/ms-dep-pkg-cud?sort=semver)
![license](https://img.shields.io/github/license/ortelius/ms-dep-pkg-cud)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/ms-dep-pkg-cud/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/ms-dep-pkg-cud/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/ms-dep-pkg-cud/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/ms-dep-pkg-cud/workflows/CodeQL/badge.svg)
[![OpenSSF
-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-dep-pkg-cud)


![Discord](https://img.shields.io/discord/722468819091849316)

> Version 10.0.0

RestAPI endpoint for retrieving SBOM data to a component

## Path Table

| Method | Path | Description |
| --- | --- | --- |
| GET | [/health](#gethealth) | Health |
| GET | [/msapi/deppkg](#getmsapideppkg) | Get Comp Pkg Deps |

## Reference Table

| Name | Path | Description |
| --- | --- | --- |
| DepPkg | [#/components/schemas/DepPkg](#componentsschemasdeppkg) |  |
| DepPkgs | [#/components/schemas/DepPkgs](#componentsschemasdeppkgs) |  |
| HTTPValidationError | [#/components/schemas/HTTPValidationError](#componentsschemashttpvalidationerror) |  |
| StatusMsg | [#/components/schemas/StatusMsg](#componentsschemasstatusmsg) |  |
| ValidationError | [#/components/schemas/ValidationError](#componentsschemasvalidationerror) |  |

## Path Details

***

### [GET]/health

- Summary  
Health

- Description  
This health check end point used by Kubernetes

#### Responses

- 200 Successful Response

`application/json`

```ts
{
  status?: string
  service_name?: string
}
```

***

### [GET]/msapi/deppkg

- Summary  
Get Comp Pkg Deps

- Description  
This is the end point used to retrieve the component's SBOM (package dependencies)

#### Parameters(Query)

```ts
compid?: Partial(integer) & Partial(null)
```

```ts
appid?: Partial(integer) & Partial(null)
```

```ts
deptype?: string
```

#### Responses

- 200 Successful Response

`application/json`

```ts
{
  data: {
    packagename?: string
    packageversion?: string
    pkgtype?: string
    name?: string
    url?: string
    summary?: string
    fullcompname?: string
    risklevel?: string
  }[]
}
```

- 422 Validation Error

`application/json`

```ts
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

## References

### #/components/schemas/DepPkg

```ts
{
  packagename?: string
  packageversion?: string
  pkgtype?: string
  name?: string
  url?: string
  summary?: string
  fullcompname?: string
  risklevel?: string
}
```

### #/components/schemas/DepPkgs

```ts
{
  data: {
    packagename?: string
    packageversion?: string
    pkgtype?: string
    name?: string
    url?: string
    summary?: string
    fullcompname?: string
    risklevel?: string
  }[]
}
```

### #/components/schemas/HTTPValidationError

```ts
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

### #/components/schemas/StatusMsg

```ts
{
  status?: string
  service_name?: string
}
```

### #/components/schemas/ValidationError

```ts
{
  loc?: Partial(string) & Partial(integer)[]
  msg: string
  type: string
}
```
