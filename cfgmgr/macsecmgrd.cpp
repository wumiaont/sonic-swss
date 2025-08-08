#include <unistd.h>
#include <signal.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>
#include <mutex>
#include <algorithm>

#include <logger.h>
#include <producerstatetable.h>
#include <macaddress.h>
#include <exec.h>
#include <tokenize.h>
#include <shellcmd.h>
#include <warm_restart.h>
#include <select.h>

#include "macsecmgr.h"

using namespace std;
using namespace swss;

/* select() function timeout retry time, in millisecond */
#define SELECT_TIMEOUT 1000

MacAddress gMacAddress;

static bool received_sigterm = false;
static struct sigaction old_sigaction;

static void sig_handler(int signo)
{
    SWSS_LOG_ENTER();

    if (old_sigaction.sa_handler != SIG_IGN && old_sigaction.sa_handler != SIG_DFL) {
        old_sigaction.sa_handler(signo);
    }

    received_sigterm = true;
    return;
}

bool check_fips_post_status(swss::DBConnector* stateDb) {
    Table m_state_fips_table(stateDb, "FIPS_STATS");
    std::vector<FieldValueTuple> values;
    bool rt = true;
    if (!m_state_fips_table.get("state", values))
    {
        SWSS_LOG_ERROR("FIPS state does not exist");
        return false;
    }
    std::string fips_post_result;
    std::string fips_enabled;
    for (auto i: values)
    {
        if (fvField(i) == "macsec_post_result")
        {
            fips_post_result = fvValue(i);
        }
        if (fvField(i) == "enabled")
        {
            fips_enabled = fvValue(i);
        }
    }
    bool enabled = (fips_enabled == "True")?true:false;
    bool passed = (fips_post_result == "passed")?true:false;
    if (enabled && !passed)
        rt = false;
    SWSS_LOG_ERROR("fips_enabled %d passed %d", enabled, passed);
    return rt;
}

int main(int argc, char **argv)
{

    try
    {
        Logger::linkToDbNative("macsecmgrd");
        SWSS_LOG_NOTICE("--- Starting macsecmgrd ---");

        /* Register the signal handler for SIGTERM */
        struct sigaction sigact = {};
        sigact.sa_handler = sig_handler;
        if (sigaction(SIGTERM, &sigact, &old_sigaction))
        {
            SWSS_LOG_ERROR("failed to setup SIGTERM action handler");
            exit(EXIT_FAILURE);
        }

        swss::DBConnector cfgDb("CONFIG_DB", 0);
        swss::DBConnector stateDb("STATE_DB", 0);

        std::vector<std::string> cfg_macsec_tables = {
            CFG_MACSEC_PROFILE_TABLE_NAME,
            CFG_PORT_TABLE_NAME,
        };

        MACsecMgr macsecmgr(&cfgDb, &stateDb, cfg_macsec_tables);

        std::vector<Orch *> cfgOrchList = {&macsecmgr};

        swss::Select s;
        for (Orch *o : cfgOrchList)
        {
            s.addSelectables(o->getSelectables());
        }

        SWSS_LOG_NOTICE("starting main loop");
        while (!received_sigterm)
        {
            Selectable *sel;
            int ret;

            ret = s.select(&sel, SELECT_TIMEOUT);
            if (ret == Select::ERROR)
            {
                SWSS_LOG_NOTICE("Error: %s!", strerror(errno));
                continue;
            }
            if (!check_fips_post_status(&stateDb))
            {
                // FIPS is enabled but post test failed.
                // Skip any macsec handling.
                SWSS_LOG_ERROR("macsecmgrd main post failed!!!");
                continue;
            }
            if (ret == Select::TIMEOUT)
            {
                macsecmgr.doTask();
                continue;
            }

            auto *c = (Executor *)sel;
            c->execute();
        }
    }
    catch(const std::exception &e)
    {
        SWSS_LOG_ERROR("Runtime error: %s", e.what());
    }
    return -1;
}
