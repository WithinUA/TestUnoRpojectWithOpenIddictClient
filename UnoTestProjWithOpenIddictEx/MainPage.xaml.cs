using OpenIddict.Client;
using static OpenIddict.Client.OpenIddictClientModels;

namespace UnoTestProjWithOpenIddictEx;

public sealed partial class MainPage : Page
{

    private readonly nint hwnd = 0;
    public MainPage()
    {
        this.InitializeComponent();
    }

    private async void Button_Click(object sender, RoutedEventArgs e)
    {
        var request = new InteractiveChallengeRequest
        {
            ProviderName = "Local",
            CancellationToken = default
        };
        var app = Application.Current as App;
        var openIddictClient = app?.Host?.Services.GetRequiredService<OpenIddictClientService>();
        try
        {

            var result = await openIddictClient.ChallengeInteractivelyAsync(request);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during OpenIddict client interaction: {ex.Message}");
        }
    }
}
