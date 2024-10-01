@load base/protocols/ssl
@load base/protocols/dns

module LLM;

option DEBUG = F;

export {
    # Define the Info record first
    type Info: record {
        ts: time &log;
        uid: string &log;
        orig_h: addr &log;
        orig_p: port &log;
        resp_h: addr &log;
        resp_p: port &log;
        proto: transport_proto &log;
        server_name: string &log;
        status: string &log;
        provider: string &log;
    };

    # Now we can redefine enum Log::ID
    redef enum Log::ID += { LOG };
}

const llm_providers: set[string] = {
    "api.openai.com",
    "chatgpt.com",
    "ab.chatgpt.com",
    "chat.openai.com",
    "platform.openai.com",
    "ai.google.dev",
    "makersuite.google.com",
    "generativelanguage.googleapis.com",
    "api.anthropic.com",
    "a-api.anthropic.com",
    "api.cohere.ai",
    "api.ai21.com",
    "api-inference.huggingface.co",
    "deepmind.google.com",
    "api.cognitive.microsoft.com",
    "bedrock-runtime.amazonaws.com",
    "api.us-south.natural-language-understanding.watson.cloud.ibm.com",
    "api.replicate.com",
    "api.aleph-alpha.com",
    "api.forefront.ai",
    "api.stability.ai",
    "api.assemblyai.com",
    "api.scale.com",
    "api.nvcf.nvidia.com",
    "api.inflection.ai",
    "api.meta.com",
    "api.perplexity.ai",
    "api.mistral.ai",
    "api.mosaicml.com",
    "api.allenai.org",
    "api.rasa.com",
    "api-free.deepl.com",
    "api.deepl.com",
    "api.together.xyz",
    "claude.ai",
    "api.elevenlabs.io",
    "api.writesonic.com",
    "api.jasper.ai",
    "api.textsynth.com",
    "api.goose.ai",
    "api.nlpcloud.io",
    "api.inferkit.com",
    "api.deepinfra.com",
    "api.runwayml.com",
    "api.textcortex.com",
    "api.writesonic.com",
    "api.copy.ai",
    "api2.cursor.sh"
} &redef;

const whitelist: set[string] = {
    "api.openai.com",
    "api.anthropic.com",
} &redef;

const blacklist: set[string] = {
    "api.someuntrustedprovider.com",
} &redef;

function debug_print(msg: string)
{
    if (DEBUG)
    {
        print fmt("Debug: %s", msg);
    }
}

event zeek_init()
{
    debug_print("LLM Traffic Monitor script loaded!");
    Log::create_stream(LLM::LOG, [$columns=Info, $path="llm_traffic"]);
}

function check_llm_provider(server_name: string, c: connection)
{
    debug_print(fmt("check_llm_provider called with server_name: %s", server_name));
    
    local status: string;
    local provider: string = server_name;

    if (server_name in whitelist)
    {
        status = "Allowed (whitelisted)";
    }
    else if (server_name in blacklist)
    {
        status = "Blocked (blacklisted)";
    }
    else if (server_name in llm_providers)
    {
        status = "Detected (unlisted)";
    }
    else
    {
        debug_print(fmt("server_name %s not found in any list", server_name));
        return;
    }

    debug_print(fmt("Logging LLM traffic for %s (Status: %s, Provider: %s)", server_name, status, provider));

    local info: Info = [
        $ts=network_time(),
        $uid=c$uid,
        $orig_h=c$id$orig_h,
        $orig_p=c$id$orig_p,
        $resp_h=c$id$resp_h,
        $resp_p=c$id$resp_p,
        $proto=get_port_transport_proto(c$id$resp_p),
        $server_name=server_name,
        $status=status,
        $provider=provider
    ];

    Log::write(LLM::LOG, info);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    local host = "";
    if (c?$http && c$http?$host)
    {
        host = c$http$host;
    }
    debug_print(fmt("http_request event triggered. Method: %s, URI: %s, Host: %s", method, original_URI, host));
    
    if (host == "")
    {
        debug_print("Host is empty. Checking URI for known providers...");
        for (provider in llm_providers)
        {
            if (provider in original_URI)
            {
                debug_print(fmt("Found provider %s in URI %s", provider, original_URI));
                check_llm_provider(provider, c);
                return;
            }
        }
    }
    else
    {
        check_llm_provider(host, c);
    }
}

event ssl_established(c: connection)
{
    if (c$ssl?$server_name)
    {
        debug_print(fmt("SSL connection established with server name: %s", c$ssl$server_name));
        check_llm_provider(c$ssl$server_name, c);
    }
    else if (c$ssl?$subject)
    {
        debug_print(fmt("SSL connection established with subject: %s", c$ssl$subject));
        check_llm_provider(c$ssl$subject, c);
    }
    else
    {
        debug_print(fmt("SSL connection established without server name or subject. Dest IP: %s", c$id$resp_h));
    }
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    debug_print(fmt("dns_request event triggered for query: %s", query));
    check_llm_provider(query, c);
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
    debug_print(fmt("DNS A reply for %s: %s", ans$query, a));
    check_llm_provider(ans$query, c);
}