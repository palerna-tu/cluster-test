package phylake.kubernetes

inputParams = input.parameters {
	input.parameters
}

else = data.inventory.parameters {
	data.inventory.parameters
}

else = set() {
	true
}

excludedNamePatterns = {name | name := inputParams.excludedNamePatterns[_]} {
	inputParams.excludedNamePatterns
}

else = ["cm-acme-http-solver-*"] {
	true
}

regexMatchesResultList(stringToCheck, patternsList) = matchVerificationList {
	matchVerificationList := [{"pattern": pattern, "match": match} |
		pattern := patternsList[_]
		match := re_match(pattern, stringToCheck)
	]
}

review = input.review {
	input.review
	not input.request
}

else = input.request {
	input.request
	not input.review
}

else = {"object": input, "oldObject": null, "operation": "CREATE"} {
	not input.request
	not input.review
}

objectNameMatchFound(patternsList) {
	objName := review.object.metadata.name
	nameToPatternMatchList := regexMatchesResultList(objName, patternsList)
	any([patternMatch |
		it := nameToPatternMatchList[_]
		patternMatch = it.match
	])
}

objectNameMatchNotFound(patternsList) {
	not objectNameMatchFound(patternsList)
}

getContainerName(containerName) = result {
	containerName != ""
	result := sprintf("containerName: %v\n", [containerName])
}

else = "" {
	true
}

getFullField(resource, property, containerType) = result {
	resource != ""
	property != ""
	result := sprintf("field: %v.%v\n", [resource, property])
}

else = result {
	property != ""
	containerType != ""
	metadata.specPath != ""
	result := sprintf("field: %v.%v.%v\n", [metadata.specPath, containerType, property])
}

else = result {
	containerType != ""
	metadata.specPath != ""
	result := sprintf("field: %v.%v\n", [metadata.specPath, containerType])
}

else = result {
	property != ""
	metadata.specPath != ""
	result := sprintf("field: %v.%v\n", [metadata.specPath, property])
}

else = result {
	property != ""
	result := sprintf("field: %v\n", [property])
}

else = "" {
	true
}

metadata = result {
	validKinds := ["ReplicaSet", "ReplicationController", "Deployment", "StatefulSet", "DaemonSet", "Job"]
	any([good | good := review.object.kind == validKinds[_]])
	spec := object.get(review.object, "spec", {})
	template := object.get(spec, "template", {})
	result := {
		"objectSpec": object.get(template, "spec", {}),
		"objectMetadata": object.get(template, "metadata", {}),
		"rootMetadata": object.get(review.object, "metadata", {}),
		"specPath": sprintf("%v.spec.template.spec", [lower(review.object.kind)]),
		"jsonPath": ".spec.template.spec",
		"metadataPath": sprintf("%v.spec.template.metadata", [lower(review.object.kind)]),
	}
}

else = result {
	review.object.kind == "Pod"
	result := {
		"objectSpec": object.get(review.object, "spec", {}),
		"objectMetadata": object.get(review.object, "metadata", {}),
		"rootMetadata": object.get(review.object, "metadata", {}),
		"specPath": sprintf("%v.spec", [lower(review.object.kind)]),
		"jsonPath": ".spec",
		"metadataPath": sprintf("%v.metadata", [lower(review.object.kind)]),
	}
}

else = result {
	review.object.kind == "CronJob"
	spec := object.get(review.object, "spec", {})
	jobTemplate := object.get(spec, "jobTemplate", {})
	jtSpec := object.get(jobTemplate, "spec", {})
	jtsTemplate := object.get(jtSpec, "template", {})
	result := {
		"objectSpec": object.get(jtsTemplate, "spec", {}),
		"objectMetadata": object.get(jtsTemplate, "metadata", {}),
		"rootMetadata": object.get(review.object, "metadata", {}),
		"specPath": sprintf("%v.spec.jobtemplate.spec.template.spec", [lower(review.object.kind)]),
		"jsonPath": ".spec.jobtemplate.spec.template.spec",
		"metadataPath": sprintf("%v.spec.jobtemplate.spec.template.metadata", [lower(review.object.kind)]),
	}
}

getFullXPath(property, containerName, containerType) = result {
	property != ""
	containerName != ""
	containerType != ""
	metadata.jsonPath != ""
	result := sprintf("JSONPath: %v.%v[?(@.name == \"%v\")].%v\n", [metadata.jsonPath, containerType, containerName, property])
}

else = result {
	containerName != ""
	containerType != ""
	metadata.specPath != ""
	result := sprintf("JSONPath: %v.%v[?(@.name == \"%v\")]\n", [metadata.jsonPath, containerType, containerName])
}

else = result {
	property != ""
	metadata.jsonPath != ""
	result := sprintf("JSONPath: %v.%v\n", [metadata.jsonPath, property])
}

else = result {
	property != ""
	result := sprintf("JSONPath: .%v\n", [property])
}

else = "" {
	true
}

getValidValues(validValues) = result {
	validValues != ""
	result := sprintf("validValues: %v\n", [validValues])
}

else = "" {
	true
}

objectApiVersion = sprintf("%s", [review.object.apiVersion]) {
	review.object.apiVersion
}

else = "Unknown" {
	true
}

objectKind = sprintf("%s", [review.object.kind]) {
	review.object.kind
}

else = "Unknown" {
	true
}

objectName = sprintf("%s", [review.object.metadata.name]) {
	review.object.metadata.name
}

else = "Unknown" {
	true
}

inputObject = {
	"review": input.review,
	"parameters": inputParams,
} {
	input.review
	not input.request
}

else = {"review": input.request, "parameters": inputParams} {
	input.request
	not input.review
}

else = {"review": {"object": input, "oldObject": null, "operation": "CREATE"}, "parameters": inputParams} {
	not input.request
	not input.review
}

objectNamespace = inputObject.review.object.metadata.namespace {
	inputObject.review.object.metadata
	inputObject.review.object.metadata.namespace
}

else = data.inventory.conftestnamespace {
	data.inventory.conftestnamespace
}

else = "default" {
	true
}

printReasonWithObject(policyName, reason, resource, property, containerName, containerType, validValues) = result {
	title := sprintf("%v violated: %v\n\n", [policyName, reason])
	container := getContainerName(containerName)
	fullField := getFullField(resource, property, containerType)
	vv := getValidValues(validValues)
	object := sprintf("object:\n  apiVersion: %v\n  kind: %v\n  metadata:\n    name: %v\n    namespace: %v\n", [objectApiVersion, objectKind, objectName, objectNamespace])
	jsonPath := getFullXPath(property, containerName, containerType)
	result := concat("", [title, container, fullField, vv, "\n", object, jsonPath])
}

exclusionAnnotationsPrefixes = ["phylake.io/policy.exclusion.", "cloud.syncier.com/policy.exclusion."]

isValidExclusionAnnotation(annotation) {
	count([it |
		it := exclusionAnnotationsPrefixes[_]
		startswith(annotation, it)
	]) > 0
}

else = false {
	true
}

getPolicyExclusionAnnotations(object) = exclusionAnnotations {
	annotations := object.metadata.annotations
	not is_null(annotations)
	exclusionAnnotations := [i |
		annotations[i]
		isValidExclusionAnnotation(i)
	]
}

else = [] {
	true
}

getPolicyExclusionAnnotationsAtNamespaceLevel(object) = exclusionAnnotations {
	annotations := data.inventory.cluster.v1.Namespace[objectNamespace].metadata.annotations
	not is_null(annotations)
	exclusionAnnotations := [i |
		annotations[i]
		isValidExclusionAnnotation(i)
	]
}

else = [] {
	true
}

has_field(object, field) {
	_ = object[field]
}

getPolicyExclusionAnnotationsAtTemplateLevel(object) = exclusionAnnotations {
	has_field(object, "spec")
	has_field(object.spec, "template")
	has_field(object.spec.template, "metadata")
	has_field(object.spec.template.metadata, "annotations")
	annotations := object.spec.template.metadata.annotations
	not is_null(annotations)
	exclusionAnnotations := [i |
		annotations[i]
		isValidExclusionAnnotation(i)
	]
}

else = [] {
	true
}

getOwnerFor(reference, namespace) = owner {
	is_string(namespace)
	count(namespace) > 0
	owner := data.inventory.namespace[namespace][reference.apiVersion][reference.kind][reference.name]
	not is_null(owner)
}

else = owner {
	owner := data.inventory.cluster[reference.apiVersion][reference.kind][reference.name]
	not is_null(owner)
}

else = null {
	true
}

getPolicyExclusionAnnotationsOnOwners(object) = exclusionAnnotations {
	parents := [owner |
		reference := object.metadata.ownerReferences[_]
		owner := getOwnerFor(reference, object.metadata.namespace)
		not is_null(owner)
	]

	grandParents := [owner |
		metadata := parents[_].metadata
		reference := metadata.ownerReferences[_]
		owner := getOwnerFor(reference, metadata.namespace)
		not is_null(owner)
	]

	owners := array.concat(parents, grandParents)
	exclusionAnnotations := [annotation |
		owners[_].metadata.annotations[annotation]
		isValidExclusionAnnotation(annotation)
	]
}

isExclusionAnnotationForConstraint(annotation, constraintName) {
	count([it |
		it := exclusionAnnotationsPrefixes[_]
		exclusionAnnotation := concat("", [it, constraintName])
		annotation == exclusionAnnotation
	]) > 0
}

else = false {
	true
}

thereIsExclusionAnnotationForConstraint(constraintName) {
	not inputParams.ignoreRiskAcceptances
	exclusionAnnotationsObjectLevel := getPolicyExclusionAnnotations(review.object)
	exclusionAnnotationsTemplateLevel := getPolicyExclusionAnnotationsAtTemplateLevel(review.object)
	exclusionAnnotationsNamespaceLevel := getPolicyExclusionAnnotationsAtNamespaceLevel(review.object)
	exclusionAnnotationsOwners := getPolicyExclusionAnnotationsOnOwners(review.object)
	exclusionAnnotations := array.concat(exclusionAnnotationsObjectLevel, array.concat(exclusionAnnotationsTemplateLevel, array.concat(exclusionAnnotationsNamespaceLevel, exclusionAnnotationsOwners)))

	count([it |
		it := exclusionAnnotations[_]
		isExclusionAnnotationForConstraint(it, constraintName)
	]) > 0
}

else = false {
	true
}

thereIsNoExclusionAnnotationForConstraint(constraintName) {
	not thereIsExclusionAnnotationForConstraint(constraintName)
}

else = false {
	true
}

rule[reason] {
	review.object.kind == "Ingress"
	thereIsNoExclusionAnnotationForConstraint("enforceingresstls")
	objectNameMatchNotFound(excludedNamePatterns)
	not review.object.spec.tls
	reason := printReasonWithObject("EnforceIngressTLS", "Should have TLS enabled", "ingress", "spec.tls", "", "", "")
}

rule[reason] {
	review.object.kind == "Ingress"
	thereIsNoExclusionAnnotationForConstraint("enforceingresstls")
	objectNameMatchNotFound(excludedNamePatterns)
	entry := review.object.spec.tls[_]
	not entry.secretName
	reason := printReasonWithObject("EnforceIngressTLS", "Should have secretName within TLS config", "ingress", "spec.tls.secretName", "", "", "")
}

objResult = input {
	is_object(input)
	is_string(input.msg)
}

else = {"msg": input} {
	is_string(input)
}

else = {"msg": "Invalid input given. See details for more information about.", "details": input} {
	true
}

deny[reason] {
	review.object

	trace(concat("", ["CONFTEST CONVERSION INPUT:", json.marshal(inputObject)]))
	results := rule with input as inputObject

	result := results[_]
	reason = objResult.msg with input as result

	trace(concat("", ["CONFTEST CONVERSION REASON:", json.marshal(reason)]))
}

default is_gatekeeper = false

is_gatekeeper {
	has_field(input, "review")
	has_field(input.review, "object")
}

resource = sprintf("%s/%s (%s)", [review.object.kind, review.object.metadata.name, review.object.metadata.namespace]) {
	review.object.kind
	review.object.metadata.name
	review.object.metadata.namespace
}

else = sprintf("%s/%s", [review.object.kind, review.object.metadata.name]) {
	review.object.kind
	review.object.metadata.name
}

else = review.object.kind {
	review.object.kind
}

else = "Unknown" {
	true
}

hasOldObject {
	has_field(review, "oldObject")
	not is_null(review.oldObject)
	review.oldObject != {}
}

resultMsg(it) = it {
	is_string(it)
}

else = it.msg {
	is_object(it)
	it.msg
}

else = "" {
	true
}
