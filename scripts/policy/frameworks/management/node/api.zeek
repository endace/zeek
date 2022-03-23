##! The Management event API of data cluster nodes. The API consists of event
##! pairs, like elsewhere in the Management, Supervisor, or Control frameworks.

@load policy/frameworks/management/types

module Management::Node::API;

export {
	## Management agents send this event to every Zeek data cluster node to
	## retrieve the current value of a variable in the script layer's global
	## namespace, referenced by the given identifier (i.e. variable
	## name). This is the agent-node equivalent of
	## :zeek:see:`Management::Controller::API::get_id_value_request`.
	##
	## reqid: a request identifier string, echoed in the response event.
	##
	## id: the name of the variable whose value to retrieve.
	global get_id_value_request: event(reqid: string, id: string);

	## Response to a get_id_value_request event. The nodes send this back
	## to the agent. This is the agent-node equivalent of
	## :zeek:see:`Management::Controller::API::get_id_value_response`.
	##
	## reqid: the request identifier used in the request event.
	##
	## result: a :zeek:see:`Management::Result` record covering one Zeek data
	##     cluster node managed by the agent. The data field contains a string
	##     with the JSON rendering of the value (as produced by :zeek:id:`to_json`,
	##     including the error strings it potentially returns).
	global get_id_value_response: event(reqid: string, result: Management::Result);
}
