# @TEST-EXEC: zeek ../../../scripts tuning/json-logs %INPUT
# @TEST-EXEC: cat logconf.log| jq -cr .props > splunk.props
# @TEST-EXEC: cat logconf.log| jq -cr .transforms  > splunk.trans
# @TEST-EXEC: btest-diff splunk.props
# @TEST-EXEC: btest-diff splunk.trans

redef schema::doJSONschema = T; # create one big schema ("all")
redef schema::doRSTdoc = T; # log line per log with its JSON schema and RST
redef schema::doAvro = T; # log line per log with its JSON schema and Avro schema
redef schema::doSplunk = T; # create additional log with Splunk config {props,transforms}.conf
redef schema::doWeb = T; # create self-contained webpage description
