using Uno.UI.Hosting;
using UnoTestProjWithOpenIddictEx;

var host = UnoPlatformHostBuilder.Create()
    .App(() => new App())
    .UseWebAssembly()
    .Build();

await host.RunAsync();
