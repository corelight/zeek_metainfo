# @TEST-EXEC: zeek ../../../scripts tuning/json-logs %INPUT
# @TEST-EXEC: cat logschema.log| jq '. | select(.name=="web")' | jq -cr .web > schema.html
# @TEST-EXEC: btest-diff schema.html
# @TEST-EXEC: tidy -e schema.html

redef schema::doJSONschema = T; # create one big schema ("all")
redef schema::doRSTdoc = T; # log line per log with its JSON schema and RST
redef schema::doAvro = T; # log line per log with its JSON schema and Avro schema
redef schema::doSplunk = T; # create additional log with Splunk config {props,transforms}.conf
redef schema::doWeb = T; # create self-contained webpage description
