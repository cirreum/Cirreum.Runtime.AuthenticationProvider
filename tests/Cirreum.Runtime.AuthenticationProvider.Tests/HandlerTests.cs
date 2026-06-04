namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

/// <summary>
/// Confidence tests for the framework-shipped <see cref="AnonymousAuthenticationHandler"/>
/// and <see cref="AmbiguousRequestAuthenticationHandler"/>. Both handlers have trivial
/// behavior; tests guard against regression in the always-NoResult / always-Fail contracts.
/// </summary>
public class HandlerTests {

	[Fact]
	public async Task AnonymousHandler_AuthenticateAsync_AlwaysReturnsNoResult() {
		var handler = await CreateAnonymousHandler();

		var result = await handler.AuthenticateAsync();

		result.None.Should().BeTrue();
	}

	[Fact]
	public async Task AmbiguousHandler_AuthenticateAsync_AlwaysFailsWithConfiguredMessage() {
		var customMessage = "Custom failure message for this test.";
		var handler = await CreateAmbiguousHandler(opts => opts.FailureMessage = customMessage);

		var result = await handler.AuthenticateAsync();

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Be(customMessage);
	}

	[Fact]
	public async Task AmbiguousHandler_AuthenticateAsync_DefaultsToDescriptiveMessage() {
		var handler = await CreateAmbiguousHandler();

		var result = await handler.AuthenticateAsync();

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("Unable to determine authentication method");
	}

	private static async Task<AnonymousAuthenticationHandler> CreateAnonymousHandler() {
		var options = new TestOptionsMonitor<AuthenticationSchemeOptions>(new AuthenticationSchemeOptions());
		var handler = new AnonymousAuthenticationHandler(options, NullLoggerFactory.Instance, UrlEncoder.Default);
		await handler.InitializeAsync(
			new AuthenticationScheme(AuthenticationSchemes.Anonymous, null, typeof(AnonymousAuthenticationHandler)),
			new DefaultHttpContext());
		return handler;
	}

	private static async Task<AmbiguousRequestAuthenticationHandler> CreateAmbiguousHandler(
		Action<AmbiguousRequestAuthenticationOptions>? configure = null) {
		var opts = new AmbiguousRequestAuthenticationOptions();
		configure?.Invoke(opts);
		var options = new TestOptionsMonitor<AmbiguousRequestAuthenticationOptions>(opts);
		var handler = new AmbiguousRequestAuthenticationHandler(options, NullLoggerFactory.Instance, UrlEncoder.Default);
		await handler.InitializeAsync(
			new AuthenticationScheme(AuthenticationSchemes.Ambiguous, null, typeof(AmbiguousRequestAuthenticationHandler)),
			new DefaultHttpContext());
		return handler;
	}

	private sealed class TestOptionsMonitor<T>(T value) : IOptionsMonitor<T> {
		public T CurrentValue { get; } = value;
		public T Get(string? name) => this.CurrentValue;
		public IDisposable OnChange(Action<T, string> listener) => new NullDisposable();

		private sealed class NullDisposable : IDisposable {
			public void Dispose() { }
		}
	}

}
