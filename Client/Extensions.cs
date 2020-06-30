using System.Threading.Tasks;
using Microsoft.JSInterop;

public static class Extensions
{
    public static async Task<bool> IsScrolled(IJSRuntime jsRuntime, string element) {
        var value = (int)await jsRuntime.InvokeAsync<int>("blazorHelpers.scrollPosition", element);

        return value != 100;
    }

    public static ValueTask ScrollToEnd(IJSRuntime jsRuntime, string element)
    {
        return jsRuntime.InvokeVoidAsync("blazorHelpers.scrollToEnd", element);
    }
}