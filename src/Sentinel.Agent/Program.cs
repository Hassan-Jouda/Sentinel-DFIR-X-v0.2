using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sentinel.Agent;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "Sentinel DFIR Agent");
builder.Services.AddHostedService<AgentWorker>();
await builder.Build().RunAsync();
