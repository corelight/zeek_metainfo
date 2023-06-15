# Zeek_metadata

## Getting started

Script & utility code to extract from zeek information (metadata) about the logs it will produce in its current configuration.  Multiple export formats included: JSON schema, RST doc files, HTML manual-in-a-page, Splunk configuration files, and Avro schemas.

## Status

v1.0 - functionality in the state discribed in the 2022 Zeek Week talk, or better.

## Installation
zkg!
Then edit the options at the top so it just produces the output you want, or change using Configuration framework (or redef).

## Usage
Logs are produced with fields defining the output, depending on configuration.  Logs are only produced on startup.  The main log is logschema, but logsplunk can also be enabled.  To use the files, extract the fields needed (e.g., jq .text logschema.log) then remove the quotes and convert \n to a ^J and \" to ", helper scripts are available in the package.

### Examples

Valid fields in logschema are:
  * `name` (log name, i.e. conn)
  * `schema` (JSON)
  * `text` (rst)
  * `avro` (apache Avro)
  * `web` (HTML)

```
# get Avro schema from JSON-formatted zeek log
jq .avro logschema.log | ./fixup.py > logschema.avro

# get HTML
jq .web logschema.log | grep -v '^null$' | ./fixup > logschema.html

# get JSON schema from zeek-style (tab-separated) log file
cat logschema.log | zeek-cut -c schema | ./fixup_json.py > logschema.json

# break 'em all up into files
for n in $(jq -r .name logschema.txt ); do
  jq '. | select(.name=="'$n'")' logschema.txt |jq .text | ./fixup.py > $n.rst
  jq '. | select(.name=="'$n'")' logschema.txt |jq .schema | sed  -e 's/[\][\]n/ /g' -e 's/[\]n/\n/g' -e 's/[\]"/"/g' -e 's/^"//' -e 's/"$//' > $n.json
  jq '. | select(.name=="'$n'")' logschema.txt |jq .avro | ./fixup.py > $n.avsc
done

```

One note about the "html" output - to use with most environments you will need to save to disk and open with browser, the code isn't valid for "open attachment" type access.

## Roadmap

Add tests!

JSONExtras is a bit of a hack, would be better to be able to add "as-if" it were in the record walk, then it would flow into RST, Avro, ... not just into JSON Schema

The JSON schemea is somewhat version dependent, would like it set it to the most commonly supported version.
The Avro schema needs production testing especially around subrecords.
HTML could use some additional table prettification (definition lists like conn_history) and validation.

As the new BIFs come available, add top-level log descriptions and "sources" to define base log fields vs those added from packages.  Malcom may be an interesting next format!  OCSF was discussed but seems very early and may not in fact be a good match.  Would be great to spell out how to track checksum changes in Splunk to alert on schema variance.  Be great to be able to index into the html (can anchors be in the tables? would they expand if used?).

## Authors and acknowledgment
Thanks to Seth & Jon for the orig tools, and Kevin Kerber for hounding me to write it.  V1.0 hacking mostly done by Steve Smoot with key bugfixes from Justin Azoff.

## License
BSD


