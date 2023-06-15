##! Describe the current Zeek log output in various ways (per options).

module schema;

export {
	redef enum Log::ID += { LOG, LOG2 };

	type Info: record {
		## log file name
		name: string &log &default="";
		## RST documentation of schema as a string
		text: string &log &default="";
		## JSON schema as a string
		schema: string &log &default="";
		## Avro Schema as a string
		avro: string &log &default="";
		## Webpage version of schema
		web: string &log &optional;
	};

	type InfoSplunk: record {
		## Splunk props.conf for this log schema
		props: string &log &default="";
		## Splunk transforms.conf for this log schema
		transforms: string &log &default="";
		## Enable users to quickly validate if this info has changed
		checksum: string &log &default="";
	};

	option doJSONschema = T &redef; # create one big schema ("all")
	option doRSTdoc = T &redef; # log line per log with its JSON schema and RST
	option doAvro = F &redef; # log line per log with its JSON schema and Avro schema
	option doSplunk = F &redef; # create log with Splunk config {props,transforms}.conf
	option doWeb = F &redef; # create self-contained webpage description

	option splunkPrefix = "zeek_" &redef; # or corelight_ or bro_ or zeek_ all for compat at your installation

	option AvroNamespace = "org.zeek.logs" &redef; # or "com.example.zeek.logs"
	option AvroSubrecords = "" &redef; # . is illegal in avro field names, replace with this string (need to get zeek to play along) - "" means do subrecords else keep flat and replace dots, e.g. "_" makes id_orig_h - note you will also need to redef Log::default_scope_sep to this value
        ## some systems add additional fields not defined in the Zeek side
        ## enable generic add based on JSON version and log name
	option AvroExtras = ""  &redef; # add in non-script prefixed fields - like JSONExtras (below)

        type JSON_extra_field_formatter: function(logname: string, rev6: bool): string;
	option JSONExtras: JSON_extra_field_formatter = function(s:string, rev6:bool):string {return "";} &redef;
	option JSONrev6orLater = F &redef;
	option JSONtitle = "Our Logs" &redef;
	option JSONid = "https://zeek.org/zeek-schema.json" &redef;
	option JSONdesc = "Definition of all of the potential logs for this installation" &redef;

	global log_schema: event(rec: Info);
	global log_splunk: event(rec: InfoSplunk);
}

option webPrefix = "<!DOCTYPE html><html>  <head>    <style type=\"text/css\">      table.GeneratedTable {   width: 100%;   background-color: #ffffff;   border-collapse: collapse;   border-width: 2px;   border-color: #ffcc00;   border-style: solid;   color: #000000;      }      table.GeneratedTable td, table.GeneratedTable th {   border-width: 2px;   border-color: #ffcc00;   border-style: solid;   padding: 3px;      }      table.GeneratedTable thead {   background-color: #ffcc00;      }      /* Style the button that is used to open and close the collapsible content */      .collapsible {   background-color: #eee;   color: #444;   cursor: pointer;   padding: 18px;   width: 100%;   border: none;   text-align: left;   outline: none;   font-size: 15px;      }      /* Add a background color to the button if it is clicked on (add the .active class with JS), and when you move the mouse over it (hover) */      .active, .collapsible:hover {   background-color: #ccc;      }      /* Style the collapsible content. Note: hidden by default */      .content {      padding: 0 18px;      display: none;      overflow: hidden;      background-color: #f1f1f1;      }                </style>    <script type=\"text/javascript\">    </script>  <title>Log Definitions</title></head>  <body>    <h1>Logs!!!</h1>    <p>Here we intro the whole log guide.</p>"
    &redef;

option webPostfix = "    <script type=\"application/javascript\">\n      var coll = document.getElementsByClassName(\"collapsible\");\n      var i;\n\n      for (i = 0; i < coll.length; i++) {\n   coll[i].addEventListener(\"click\", function() {\n       this.classList.toggle(\"active\");\n       var content = this.nextElementSibling;\n       if (content.style.display === \"block\") {\n    content.style.display = \"none\";\n       } else {\n    content.style.display = \"block\";\n       }\n   });\n      }       \n    </script>\n  </body>\n</html>\n"
    &redef;

option excludedLogs: set[string] = set() &redef;

function first_json_type_translator(typestr: string): string &is_used
	{
	if ( /^(set|vector)/ in typestr )
		return "array";
	else if ( /^(double|interval)/ in typestr )
		return "number";
	else if ( /^(count|int|port)/ in typestr )
		return "integer";
	else if ( /^(enum|string|addr|subnet|pattern)/ in typestr )
		return "string";
	else if ( /^(bool)/ in typestr )
		return "boolean";
	else if ( typestr == "time" )
		return typestr;
	else
		{
		## probably should Report a problem here XXX
		return typestr;
		}
	}

function json_type_translator(typestr: string): string
	{
	if ( /^(set|vector)/ in typestr )
		return "array";
	else if ( /^(double|interval)$/ in typestr )
		return "number";
	else if ( /^(enum|string|subnet|pattern|file)$/ in typestr )
		return "string";
	else if ( /^(bool)$/ in typestr )
		return "boolean";
	else
		return typestr;
	}

global json_types_that_are_refs: set[string] = {
	"addr",
	"count",
	"int",
	"port",
	"time",
};

function type_or_ref(json_type: string): string
	{
	if (json_type in json_types_that_are_refs)
		return fmt("\"$ref\": \"#/definitions/%s\"", json_type);
	else 
		return fmt("\"type\": \"%s\"", json_type);
	}

function pattern_to_js_string(pat: pattern): string
	{
	local regex = cat(pat);
	regex = gsub(regex, /\(\^\?/, ""); # Optional left anchors
	regex = gsub(regex, /\/\^\?/, "^"); # Optional left anchor to required left anchor (and remove beginning slash)
	regex = gsub(regex, /\$\?\)/, ""); # Optional right anchors
	regex = gsub(regex, /\$\?\//, "$"); # Optional right anchor to required right anchor (and remove ending slash)
	regex = gsub(regex, /\\/, "\\\\\\\\"); # Fix up backslashes
	return regex;
	}

function avro_type_translator(typestr: string): string
	{
	if ( /^(set|vector)/ in typestr )
		return "array";
	else if ( /^(count|int)/ in typestr )
		return "long";
	else if ( /^(port)/ in typestr )
		return "int";
	else if ( /^(double|interval)/ in typestr )
		return "double";
	else if ( /^(enum|string|addr|subnet|pattern)/ in typestr )
		return "string";
	else if ( /^(bool)/ in typestr )
		return "boolean";
	else if ( typestr == "time" )
		return "string";
	else
		{
		## probably should Report a problem here XXX, print for now
		print fmt("What is type %s in avro type gen", typestr);
		return typestr;
		}
	}

function htmlize_emphasis(s: string): string
	{
	local out = "";
	local inquote = F;
	local maybe = " ";
	for ( c in s )
		{
		if ( maybe != " " )
			{
			if ( /[-a-zA-Z0-9_]/ in c )
				{
				inquote = T;
				out += "<b>" + c;
				}
			else
				{
				out += maybe;
				}
			maybe = " ";
			}
		else
			{
			if ( c == "*" || c == "`" )
				{
				if ( inquote )
					{
					out += "</b>";
					inquote = F;
					}
				else
					maybe = c;
				}
			else
				out += c;
			}
		}
	return out;
	}

type join_function: function(field: string, new_lines: vector of string): string;

function join_lines_json(field: string, new_lines: vector of string): string
	{
	return join_string_vec(new_lines, ",\n");
	}

function join_lines_newline(field: string, new_lines: vector of string): string
	{
	return join_string_vec(new_lines, "\n");
	}

function join_lines_avro_subrecords(field: string, new_lines: vector of string): string
	{
	local header = fmt("   {\n      \"name\": \"%s\",\n      \"type\": [\n        \"null\",{\n        \"type\": \"record\",\n        \"name\": \"%sRecord\",\n        \"fields\": [\n", field, field);
	local footer = "          ]\n        }\n      ]    }";
	return header + join_string_vec(new_lines, ",\n") + footer;
	}

function join_lines_avro_flat(field: string, new_lines: vector of string): string
	{
	return join_string_vec(new_lines, ",\n");
	}

type format_function: function(outer_field: string, field: string, desc: string, meta: record_field, cnt: count, typ: any): string;

type output_formatter: record {
	format_field: format_function;
	line_joiner: join_function &optional;
	fullpath_subrecs: bool;
};

function describe_(streamid: any, typ: any, outer_field: string, rf: record_field_table, cnt: count, formatter: output_formatter): vector of string
	{
	local lines = string_vec();

	local filt = Log::get_filter(streamid, "default");
	local includes: set[string] = set();
	local excludes: set[string] = set();

	if ( filt$name != "<not found>" )
		{
		if ( filt?$include )
			includes = filt$include;
		if ( filt?$exclude )
			excludes = filt$exclude;
		}

	local ordered_fields = record_type_to_vector(cat(typ));
	local first = T;
	for ( i in ordered_fields )
		{
		local field = ordered_fields[i];
		local full_field = outer_field == "" ? field : cat(outer_field, ".", field);
		local meta = rf[field];
		local is_record = /^record / in meta$type_name;
		if ( meta$log
		    && full_field !in excludes
		    && ( |includes| == 0 || full_field in includes || is_record ) )
			{
			if ( is_record )
				{
				local record_type = split_string(meta$type_name, / /)[1];
				local new_lines: vector of string;
				local next_parent_field = formatter$fullpath_subrecs ? full_field : "";
				new_lines = describe_(streamid, record_type, next_parent_field, record_fields(record_type), cnt, formatter);
				cnt += |new_lines|;
				if (formatter?$line_joiner)
					lines += formatter$line_joiner(field, new_lines);
				else
					lines += new_lines;
				}
			else
				{
				lines += formatter$format_field(outer_field, field, get_record_field_comments(fmt("%s$%s", cat(typ), field)), meta, cnt, typ);
				++cnt;
				}
			}
		}
	return lines;
	}

function describe(streamid: any, stream: Log::Stream, formatter: output_formatter): vector of string
	{
	local rf = record_fields(stream$columns);
	return describe_(streamid, stream$columns, "", rf, 1, formatter);
	}

function formatfield_splunk(outer_field: string, field: string, desc: string,
    meta: record_field, cnt: count, typ: any): string
	{
	local full_field = outer_field == "" ? field : cat(outer_field, ".", field);
	return fmt("%s::$%d", full_field, cnt);
	}

function formatfield_schema(outer_field: string, field: string, desc: string,
    meta: record_field, cnt: count, typ: any): string
	{
	local full_field = outer_field == "" ? field : cat(outer_field, ".", field);
	local field_prefix = outer_field == "" ? "" : cat(outer_field, ".");
	local json_type = json_type_translator(meta$type_name);
	local addl = type_or_ref(json_type);
	if ( json_type == "array" )
		{
		addl += fmt(", \"items\": {%s}", type_or_ref(json_type_translator(
		    split_string(meta$type_name, /( of |\[|\])/)[1])));

		if ( /^set/ in meta$type_name )
			addl += ", \"uniqueItems\": true";
		}
	# screw newlines
	desc = gsub(desc, /\n/, " ");
	# remove zeek tags
	desc = gsub(desc, /:zeek:(id|type|see|enum):/, "");
	# Nuke double quotes
	desc = gsub(desc, /\"/, "'");
	# Pretty up notes
	desc = gsub(desc, /\.\. note::/, "NOTE:");
	# Remove extra spaces
	desc = gsub(desc, /[ ]+/, " ");

	return fmt("      \"%s%s\": {%s%s}", field_prefix, field, desc != "" ? fmt(
	    "\"description\":\"%s\", ", desc) : "", addl);
	}

function fix_tables(s: string): string
	{
	## only handles definition lists (2 entries) && only one of them in the string
	local ss = split_string_all(s, /=+/);
	if ( |ss| < 11 )
		return s;
	local out: vector of string = vector();
	out += ss[0];
	local content = 8;
	local namel = |ss[1]|;
	local entries = split_string(ss[content], /\n/);
	local def = namel + |ss[2]|;
	for ( i in entries )
		{
		if ( i == 0 )
			next;
		if ( entries[i] == "" )
			break;
		out += fmt("* %s: %s", strip(entries[i][: namel]), strip(entries[i][def :]));
		}
	content += 3 + 1;
	if ( content <= |ss| && strip(ss[content]) != "" )
		out += ss[content];
	return join_string_vec(out, "\n");
	}

function makeweb_tables(s: string): string
	{
	## only handles definition lists (2 entries) && only one of them in the string
	local ss = split_string_all(s, /=+/);
	if ( |ss| < 11 )
		return s;
	local out: vector of string = vector();
	out += "<table summary=\"deets\"><tbody>";
	local content = 8;
	local namel = |ss[1]|;
	local entries = split_string(ss[content], /\n/);
	local def = namel + |ss[2]|;
	for ( i in entries )
		{
		if ( i == 0 )
			next;
		if ( entries[i] == "" )
			break;
		out += fmt("<tr><td>%s</td><td>%s</td></tr>\n", strip(entries[i][: namel]),
		    strip(entries[i][def :]));
		}
	content += 3 + 1;
	out += "</tbody></table>";
	if ( content <= |ss| && strip(ss[content]) != "" )
		out += ss[content];
	return join_string_vec(out, "\n");
	}

function makeweb_desclist(s: string): string
	{
	## handle lists of the form:
	## this is a list: \n* foo: is a foo\n* bar: is a bar...
	## doesnt currently handle trailing text after the table
	local out = string_vec();
	local ss = split_string_all(s, /\n/);
	for (i in ss) {
           if (/^\* [-a-zA-Z0-9]+:/ in ss[i]) {
              local bits=split_string(ss[i], /:/);
              out += fmt("<br><b>%s</b>:%s", bits[0][2:], bits[1]);
	      }
           else out += ss[i];
        }
	return join_string_vec(out,"\n");
	}

function source(s: string): string &is_used
	{
	if ( /^base\// in s )
		return "base";
	return s; # need to figure out how to ID packages!
	}

function formatfield_rst(outer_field: string, field: string, desc: string,
    meta: record_field, cnt: count, typ: any): string
	{
	local full_field = outer_field == "" ? field : cat(outer_field, ".", field);
	local field_prefix = outer_field == "" ? "" : cat(outer_field, ".");
	local json_type = first_json_type_translator(meta$type_name);
	if ( json_type == "array" )
		json_type = fmt("array[%s]", first_json_type_translator(split_string(
		    meta$type_name, /( of |\[|\])/)[1]));
	# hack tables
	if ( "===" in desc )
		{
		desc = fix_tables(desc);
		}
	# Remove newlines
	desc = gsub(desc, /\n/, "\n       ");
	# remove zeek tags - improve later?
	desc = gsub(desc, /:zeek:(id|type|see|enum):/, "");

	# Escape double quotes
	#				desc = gsub(desc, /\"/, "'");

	local field_full = field_prefix + field;
	if (desc == "")
		desc = fmt("The %s information.", field_full);

	local out_type = json_type == meta$type_name ? json_type : fmt("%s - %s", json_type, meta$type_name);

@if ( Version::at_least("5.2.0") )
	local out_source = source(get_record_field_declaring_script(fmt("%s$%s", typ, field)));
	return fmt("   * - ``%s`` (%s)\n     - %s\n     - %s\n", field_full, out_type, out_source, desc);
@else
	return fmt("   * - ``%s`` (%s)\n     - %s\n", field_full, out_type, desc);
@endif
	}

function formatfield_web(outer_field: string, field: string, desc: string,
    meta: record_field, cnt: count, typ: any): string
	{
	local full_field = outer_field == "" ? field : cat(outer_field, ".", field);
	local field_prefix = outer_field == "" ? "" : cat(outer_field, ".");
	local json_type = first_json_type_translator(meta$type_name);
	if ( json_type == "array" )
		json_type = fmt("array[%s]", first_json_type_translator(split_string(
		    meta$type_name, /( of |\[|\])/)[1]));
	# hack tables
	if ( "===" in desc )
		desc = makeweb_tables(desc);
        else if (/\* [-a-zA-Z0-9]+:/ in desc) 
                desc = makeweb_desclist(desc);
	# Remove newlines
	desc = gsub(desc, /\n/, " ");
	# Remove emphasis
	if ( /[*`]/ in desc )
		desc = htmlize_emphasis(desc);
	# remove zeek tags - improve later?

	local field_full = field_prefix + field;
	desc = gsub(desc, /:zeek:(id|type|see|enum):/, "");
	if (desc == "")
		desc = fmt("The %s information.", field_full);

	# Pretty up notes
	desc = gsub(desc, /\.\. note::/, "<em>NOTE</em>:");

	local out_type = json_type == meta$type_name ? json_type : fmt("%s - %s", json_type, meta$type_name);
	return fmt("<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", field_full, out_type, desc);
	}

## Format for Avro.  Note recursive records are handled in describe
function formatfield_avro(outer_field: string, field: string, desc: string,
    meta: record_field, cnt: count, typ: any): string
	{
	local field_prefix = outer_field == "" ? "" : cat(outer_field, AvroSubrecords);
	local avro_type = avro_type_translator(meta$type_name);
	local items_section = "";
	if ( avro_type == "array" )
		{
		local avro_items = avro_type_translator(split_string(meta$type_name, /( of |\[|\])/)[1]);
		items_section = fmt("{\"type\": \"array\", \"items\": \"%s\"}", avro_items);
		}
	else
		items_section = fmt("\"%s\"", avro_type);
	# Remove newlines
	desc = gsub(desc, /\n/, "\\n");
	# remove zeek tags
	desc = gsub(desc, /:zeek:(id|type|see|enum):/, "");
	# Nuke double quotes
	desc = gsub(desc, /\"/, "'");
	local full_name = field_prefix + field;
	return fmt("   {\n      \"name\": \"%s\",\n      \"type\":\ [\n        \"null\",\n        %s\n      ],\n      \"default\": null\n   }", full_name, items_section);
	}

function comp_streams(a: Log::Stream, b: Log::Stream): int
	{
	return strcmp(a$path, b$path);
	}

global formatter_avro_subs = output_formatter(
	$format_field = formatfield_avro,
	$line_joiner = join_lines_avro_subrecords,
	$fullpath_subrecs = F
);
global formatter_avro_flat = output_formatter(
	$format_field = formatfield_avro,
	$line_joiner = join_lines_avro_flat,
	$fullpath_subrecs = T
);
global formatter_schema = output_formatter(
	$format_field=formatfield_schema,
	$line_joiner=join_lines_json,
	$fullpath_subrecs=T
);
global formatter_web = output_formatter(
	$format_field=formatfield_web,
	$fullpath_subrecs=T
);
global formatter_splunk = output_formatter(
	$format_field=formatfield_splunk,
	$fullpath_subrecs=T
);
global formatter_rst = output_formatter(
	$format_field=formatfield_rst,
	$line_joiner=join_lines_newline,
	$fullpath_subrecs=T
);

function generate()
	{
	local whole = string_vec();
	local out = "";
	local schema = "";
	local avro = "";
	local log_records: set[string];
	local tout = "";
	local pout = "";
	local wout = webPrefix;

	local i = 0;
	local v: vector of Log::Stream;
	for ( id, s in Log::active_streams )
		if ( s$path !in excludedLogs )
			v += s;
	sort(v, comp_streams);

	for ( i in v )
		{
		local stream = v[i];
		local streamid: Log::ID;
		for ( id, s in Log::active_streams )
			if ( s$path == stream$path )
				{
				streamid = id;
				break;
				}

		## Per-log Preambles
		## Figure out schema
		schema = "{\n";
		schema += "  \"$schema\": \"http://json-schema.org/draft-07/schema#\",\n";
		schema += "  \"id\": \"" + JSONid + "\",\n";
		schema += fmt("  \"title\": \"" + JSONtitle + ": %s\",\n", stream$path);
		schema += fmt("  \"description\": \"Definition of the %s log at this installation (%s at %.0f).\",\n", stream$path, zeek_version(), current_time());
		schema += "  \"definitions\": {\n";
		schema += "    \"time\": {\"type\": \"string\", \"pattern\": \"[0-9]{4}-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]\\\\.?[0-9]{0,6}Z\"},\n";
		schema += "    \"port\": {\"type\": \"integer\", \"minimum\": 0, \"maximum\": 65535},\n";
		schema += "    \"count\": {\"type\": \"integer\", \"minimum\": 0, \"maximum\": 18446744073709551615},\n";
		schema += "    \"int\": {\"type\": \"integer\", \"minimum\": -9223372036854775807, \"maximum\": 9223372036854775807},\n";
		schema += "    \"addr\": {\"type\": \"string\", \"pattern\": \"" + pattern_to_js_string(ip_addr_regex) + "\"}\n},\n";
		schema += "  \"type\": \"object\",\n";
		schema += "    \"properties\": {\n";
		schema += JSONExtras(stream$path, JSONrev6orLater);
		schema += join_string_vec(describe(streamid, stream, formatter_schema), ",\n");
		schema += "},\n  \"additionalProperties\": false\n";
		schema += "}\n";

		## save schema
		whole += schema;
		local rlog: Info = [$name=stream$path, $schema=schema];

		## RST
		if ( doRSTdoc )
			{
			out = fmt(".. _ref_logs_%s:\n\n%s\n", stream$path, stream$path);
			out += gsub(stream$path, /./, "-");
@if ( Version::at_least("5.2.0") )
			out += "\n.. list-table::\n   :header-rows: 1\n   :class: longtable\n   :widths: 1 3\n\n   * - Field (Type)\n     - Source\n     - Description\n\n";
@else
			out += "\n.. list-table::\n   :header-rows: 1\n   :class: longtable\n   :widths: 1 3\n\n   * - Field (Type)\n     - Description\n\n";
@endif
			out += join_string_vec(describe(streamid, stream, formatter_rst), "\n");

			rlog$text = out;
			}

		if ( doAvro )
			{
			out = fmt("{\n  \"namespace\": \"%s\",\n  \"type\": \"record\",\n  \"name\": \"%sLog\",\n  \"doc\": \"%s record\",\n",
			    AvroNamespace, stream$path, stream$path);

			out += "\"fields\": [\n" + AvroExtras;
                        if (AvroSubrecords == "")
  			    out += join_string_vec(describe(streamid, stream, formatter_avro_subs), ",\n");
                        else
			    out += join_string_vec(describe(streamid, stream, formatter_avro_flat), ",\n");
			out += "\n  ]\n}\n";

			rlog$avro = out;
			}

		if ( doAvro || doRSTdoc )
			Log::write(schema::LOG, rlog);

		if ( doWeb )
			{
			out = fmt("    <button type=\"button\" class=\"collapsible\">%s</button>\n    <div class=\"content\">     \n <p>%s</p>\n<table class=\"GeneratedTable\" summary=\"log info\">\n <thead>   <tr> <th>Field name</th>     <th>Type<br>JSON - Zeek</th>     <th>Definition</th>   </tr> </thead>\n<tbody>\n",
			    stream$path, "Log Description goes here when zeek version allows.");
			out += join_string_vec(describe(streamid, stream, formatter_web), "\n");
			out += "\n</tbody>      </table>    </div>\n";

			wout += out;
			}
		## Splunk files
		if ( doSplunk )
			{
			local sourcetype = fmt("%s%s", splunkPrefix, stream$path);
			tout += fmt("\n\n[%s_fields1]\n", sourcetype);
			pout += fmt("\n\n[%s]\nREPORT-%s_fields = %s_fields1\n", sourcetype, sourcetype, sourcetype);
			## XXX switch to saving the pair?
			local temp = describe(streamid, stream, formatter_splunk);
			local groups = string_vec();
			for (unused in temp)
				groups += "([^\t]*)";
			tout += "REGEX = ^" + join_string_vec(groups, "\t") + "$\n";
			tout += "FORMAT = " + join_string_vec(temp, " ") + "\n\n";
			}
		}

	if ( doJSONschema )
		{
		Log::write(schema::LOG, [$name="all", $schema="{\n"
		    +
		    "  \"$schema\": \"http://json-schema.org/draft-07/schema#\",\n" + "  \"id\": \"" + JSONid + "\",\n" + "  \"title\": \"" + JSONtitle + "\",\n" + "  \"description\": \"" + JSONdesc + "\",\n" + "  \"oneOf\": [\n" + join_string_vec(whole, ",\n") + "\n]\n}"]);
		}
	if ( doWeb )
		{
		Log::write(schema::LOG, [$name="web", $web=cat(wout, webPostfix)]);
		Log::write(schema::LOG, [$name="web_debug", $web=fmt("%d", |cat(wout, webPostfix)|)]);
		}
	if ( doSplunk )
		{
		Log::write(schema::LOG2, [$props=pout, $transforms=tout, $checksum=md5_hash( tout)]);
		}
	}

event zeek_init() &priority=-1000
	{
	if ( doRSTdoc || doJSONschema )
		Log::create_stream(schema::LOG, [$columns=Info, $ev=log_schema, $path="logschema"]);

	if ( doSplunk )
		Log::create_stream(schema::LOG2, [$columns=InfoSplunk, $ev=log_splunk, $path="logconf"]);

	generate();
	}
