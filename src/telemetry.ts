import appInsights from 'applicationinsights';

// Imported first by server.ts so the SDK can instrument http/express before they load.
// The connection string comes from the App Service setting created by infra/main.bicep.
const connectionString = process.env.APPLICATIONINSIGHTS_CONNECTION_STRING;
if (connectionString) {
  appInsights.setup(connectionString).setAutoCollectConsole(true, true).start();
}
