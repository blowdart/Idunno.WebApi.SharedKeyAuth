using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;

using Idunno.WebApi.SharedKeyAuthentication;

namespace ExampleCallingApplication
{

    class Program
    {
        static void Main(string[] args)
        {
            var jsonFormatter = new JsonMediaTypeFormatter();

            // For fiddler change the base address to http://localhost.fiddler:9001

            var baseAddress = new Uri("http://localhost.fiddler:9001");

            var authenticatingClient = HttpClientFactory.Create(new SharedKeySigningHandler(Properties.Settings.Default.AccountName, Properties.Settings.Default.SharedSecret));
            authenticatingClient.BaseAddress = baseAddress;
            authenticatingClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var nonAuthenticatingClient = HttpClientFactory.Create();
            nonAuthenticatingClient.BaseAddress = baseAddress;
            nonAuthenticatingClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));


            Console.WriteLine("Press return when the receiving web app has started and you've started fiddler (if appropriate).");
            Console.ReadLine();
            Console.WriteLine();
            Console.WriteLine("GET api/Subscribers");
            var getResponse = nonAuthenticatingClient.GetStringAsync("api/Subscribers").Result;
            Console.WriteLine(getResponse);

            Console.WriteLine();
            Console.WriteLine("--------------------------------------------------------");
            Console.ReadLine();
            Console.WriteLine();


            Console.WriteLine("POST api/Subscribers with SharedSigningKeyHandler");
            var newSubscriber = new Subscriber { Email = "barry.dorrans@microsoft.com", Name = "Barry Dorrans" };
            var requestContent = new ObjectContent<Subscriber>(newSubscriber, jsonFormatter);
            var postResponse = authenticatingClient.PostAsync("api/subscribers", requestContent).Result;
            var location = postResponse.Headers.Location;
            Console.WriteLine(postResponse);

            Console.WriteLine();
            Console.WriteLine("--------------------------------------------------------");
            Console.ReadLine();
            Console.WriteLine();

            Console.WriteLine("POST api/Subscribers without SharedSigningKeyHandler");
            try
            {
                newSubscriber = new Subscriber { Email = "steveb@microsoft.com", Name = "Steve Ballmer" };
                postResponse = nonAuthenticatingClient.PostAsJsonAsync("api/Subscribers", newSubscriber).Result;
                Console.WriteLine(postResponse);
            }
            catch (Exception e)
            {
                Console.WriteLine("Ooops");
                Console.WriteLine(e);
            }

            Console.WriteLine();
            Console.WriteLine("--------------------------------------------------------");
            Console.ReadLine();
            Console.WriteLine();

            Console.WriteLine("DELETE " + location.PathAndQuery);
            var deleteResponse = authenticatingClient.DeleteAsync(location.PathAndQuery).Result;
            Console.WriteLine(deleteResponse);

            Console.WriteLine();
            Console.WriteLine("--------------------------------------------------------");
            Console.ReadLine();
            Console.WriteLine();


            Console.WriteLine("GET api/Subscribers");
            getResponse = nonAuthenticatingClient.GetStringAsync("api/Subscribers").Result;
            Console.WriteLine(getResponse);

            Console.WriteLine();
            Console.WriteLine("--------------------------------------------------------");
            Console.ReadLine();
        }
    }
}
