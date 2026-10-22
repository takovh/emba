# Convert supported Blint component fields to CycloneDX 1.5 records.
# Raw reports remain available separately; newer schema fields are not copied blindly.
def text: if type == "string" then . else "" end;
def props:
  [.[]? | select(type == "object") |
    select((.name | type) == "string" and (.value | type) == "string") |
    {name, value}];
def tree:
  . as $node | $node, ($node.components[]? | tree);
def tree_edges:
  . as $node |
  (if (($node["bom-ref"] // "") != "") then
    {ref: $node["bom-ref"], dependsOn: [$node.components[]? | .["bom-ref"] | select(type == "string")]}
  else empty end), ($node.components[]? | tree_edges);
def confidence($root; $dex; $purl):
  if $root then 1
  elif $dex then 0.2
  elif ($purl | startswith("pkg:maven/")) and
    ((.group // "") == "" or (.version // "") == "latest") then 0.2
  else
    ([.evidence.identity | if type == "array" then .[] else . end |
      .confidence | select(type == "number" and . >= 0 and . <= 1)] | first) // 0.5
  end;
def component($root; $services):
  . as $raw |
  (.purl | text) as $raw_purl |
  ($raw_purl | sub("^pkg:file/"; "pkg:generic/")) as $purl |
  ((.name | text | test("(^|/)classes([0-9]+)?(\\.dex)?$")) or
    ($purl | test("^pkg:android/classes([0-9]+)?([@?]|$)"))) as $dex |
  confidence($root; $dex; $purl) as $confidence |
  {
    original_ref: (.["bom-ref"] | text),
    root: $root,
    component: ({
      type: (if $root then "application" elif $dex then "file" else
        (if (.type == "application" or .type == "library" or .type == "file") then .type else "library" end) end),
      name: (.name | text),
      version: (.version | text),
      group: (.group | text),
      scope: "required",
      properties: ((.properties // [] | props) + [
        {name: "gst:source", value: "blint"},
        {name: "gst:confidence", value: ($confidence | tostring)},
        {name: "gst:blint:raw_purl", value: $raw_purl},
        {name: "gst:blint:raw_ref", value: (.["bom-ref"] | text)},
        {name: "gst:blint:vulnerability_lookup", value:
          (if $dex or $confidence < 0.5 or (.version // "") == "latest" then "false" else "true" end)}
      ] + [(.evidence.identity | if type == "array" then .[] else . end) |
        .methods[]? | .technique | select(type == "string") |
        {name: "gst:blint:technique", value: .}]
      + (if $root then [$services[]? | select((.name | type) == "string") |
          {name: "gst:blint:service", value: .name},
          {name: "gst:blint:service_details", value: (tojson)}] else [] end)),
      hashes: [.hashes[]? | select(type == "object") |
        select((.alg | type) == "string" and (.content | type) == "string") |
        select((.alg == "MD5" and (.content | test("^[a-fA-F0-9]{32}$"))) or
          (.alg == "SHA-256" and (.content | test("^[a-fA-F0-9]{64}$"))) or
          (.alg == "SHA-512" and (.content | test("^[a-fA-F0-9]{128}$")))) | {alg, content}]
    } + (if $purl != "" then {purl: $purl} else {} end)
      + (if (.cpe | text | test("^cpe:2\\.3:")) then {cpe: .cpe} else {} end)
      + (if (.supplier.name | text) != "" then {supplier: {name: .supplier.name}} else {} end)
      + (if (.description | text) != "" then {description: .description} else {} end))
  };
if .bomFormat != "CycloneDX" or (.metadata.component | type) != "object" then
  error("Missing CycloneDX metadata component")
else . end |
. as $bom |
# Blint may use a synthetic metadata parent containing the actual APK application.
[.metadata.component |
  if ((.purl // "") | startswith("pkg:android/")) then .
  elif ((.components // []) | length) > 0 then .components[]
  else . end |
  select(.type == "application" and ((.purl // "") | startswith("pkg:android/")))] as $roots |
{
  components: ([$roots[] | component(true; $bom.services // [])] +
    [$roots[] | .components[]? | tree | component(false; [])] +
    [$bom.components[]? | tree | component(false; [])]),
  dependencies: (($bom.dependencies // []) +
    [$roots[] | tree_edges] + [$bom.components[]? | tree_edges]),
  tools: [($bom.metadata.tools |
    if type == "object" then .components[]?
    elif type == "array" then .[] | . + {type: "application"}
    else empty end) |
    select((.name | type) == "string") |
    {type: "application", name: .name} +
      (if (.version | text) != "" then {version: .version} else {} end)] | unique_by([.name, .version])
} |
if any(.components[]; .root and .component.name != "") and
  all(.components[]; .component.name != "") and
  all(.dependencies[]; (.ref | type) == "string" and
    (.dependsOn | type) == "array" and all(.dependsOn[]; type == "string")) then .
else error("Invalid APK components or dependencies") end
