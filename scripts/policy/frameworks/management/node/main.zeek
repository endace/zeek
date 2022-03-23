##! This module provides Management framework functionality that needs to be
##! present in every data cluster node to allow Management agents to interact
##! with the data cluster nodes they manage.

@load base/frameworks/cluster

@load policy/frameworks/management/agent/config
@load policy/frameworks/management/log

@load ./api
@load ./config

module Management::Node;

# Tag our logs correctly
redef Management::Log::role = Management::NODE;

event Management::Node::API::get_id_value_request(reqid: string, id: string)
	{
	Management::Log::info(fmt("rx Management::Node::API::get_id_value_request %s", reqid));

	local val = lookup_ID(id);

	local res = Management::Result(
	    $reqid = reqid,
	    $instance = Cluster::node,
	    $data = to_json(val));

	# The following lookup_ID() result strings indicate errors:
	if ( type_name(val) == "string" )
		{
		local valstr: string = val;
		if ( valstr == "<unknown id>" || valstr == "<no ID value>" )
			{
			res$success = F;
			res$error = valstr[1:-1];
			}
		}

	Management::Log::info(fmt("tx Management::Node::API::get_id_value_response %s",
	                          Management::result_to_string(res)));
	event Management::Node::API::get_id_value_response(reqid, res);
	}

event zeek_init()
	{
	local epi = Management::Agent::endpoint_info();

	Broker::peer(epi$network$address, epi$network$bound_port, Management::connect_retry);
	Broker::subscribe(node_topic);

	# Response events automatically sent to the Management agent.
	local events: vector of any = [
	    Management::Node::API::get_id_value_response
	    ];

	for ( i in events )
		Broker::auto_publish(node_topic, events[i]);
	}
