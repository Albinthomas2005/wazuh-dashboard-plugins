import { IRouter } from 'opensearch_dashboards/server';
import { WazuhApiRoutes } from './wazuh-api';
import { WazuhElasticRoutes } from './wazuh-elastic';
import { WazuhHostsRoutes } from './wazuh-hosts';
import { UiLogsRoutes } from './wazuh-utils';
import { WazuhAiRoutes } from './wazuh-ai';

export const setupRoutes = (router: IRouter, services) => {
  WazuhApiRoutes(router, services);
  WazuhElasticRoutes(router, services);
  WazuhHostsRoutes(router, services);
  WazuhAiRoutes(router);
  UiLogsRoutes(router, services);
};
