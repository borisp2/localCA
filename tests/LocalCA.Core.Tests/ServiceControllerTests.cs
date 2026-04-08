using NSubstitute;

namespace LocalCA.Core.Tests;

public class ServiceControllerTests
{
    [Fact]
    public void RestartService_CallsStopThenStart()
    {
        var runner = Substitute.For<IProcessRunner>();

        // Stop succeeds
        runner.Run("sc", Arg.Is<string>(a => a.Contains("stop")))
            .Returns((0, ""));

        // Query returns STOPPED immediately
        runner.Run("sc", Arg.Is<string>(a => a.Contains("query")))
            .Returns((0, "STATE : 1  STOPPED"));

        // Start succeeds
        runner.Run("sc", Arg.Is<string>(a => a.Contains("start")))
            .Returns((0, ""));

        var controller = new WindowsServiceController(runner);
        var result = controller.RestartService("TestService");

        Assert.True(result);
        runner.Received().Run("sc", Arg.Is<string>(a => a.Contains("stop") && a.Contains("TestService")));
        runner.Received().Run("sc", Arg.Is<string>(a => a.Contains("start") && a.Contains("TestService")));
    }

    [Fact]
    public void RestartService_ReturnsFalseWhenStartFails()
    {
        var runner = Substitute.For<IProcessRunner>();

        runner.Run("sc", Arg.Is<string>(a => a.Contains("stop")))
            .Returns((0, ""));

        runner.Run("sc", Arg.Is<string>(a => a.Contains("query")))
            .Returns((0, "STATE : 1  STOPPED"));

        runner.Run("sc", Arg.Is<string>(a => a.Contains("start")))
            .Returns((1, "Access denied."));

        var controller = new WindowsServiceController(runner);
        var result = controller.RestartService("TestService");

        Assert.False(result);
    }

    [Fact]
    public void ServiceExists_ReturnsTrueWhenQuerySucceeds()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run("sc", Arg.Is<string>(a => a.Contains("query")))
            .Returns((0, "SERVICE_NAME: TestService\n  STATE : 4  RUNNING"));

        var controller = new WindowsServiceController(runner);
        Assert.True(controller.ServiceExists("TestService"));
    }

    [Fact]
    public void ServiceExists_ReturnsFalseWhenQueryFails()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run("sc", Arg.Is<string>(a => a.Contains("query")))
            .Returns((1, "The specified service does not exist."));

        var controller = new WindowsServiceController(runner);
        Assert.False(controller.ServiceExists("NonExistent"));
    }

    [Fact]
    public void RestartService_ReturnsFalseWhenStopFails()
    {
        var runner = Substitute.For<IProcessRunner>();

        // Stop fails with access-denied (not 0, not 1062)
        runner.Run("sc", Arg.Is<string>(a => a.Contains("stop")))
            .Returns((5, "Access is denied."));

        var controller = new WindowsServiceController(runner);
        var result = controller.RestartService("TestService");

        Assert.False(result);

        // Start should never be called when stop fails
        runner.DidNotReceive().Run("sc", Arg.Is<string>(a => a.Contains("start")));
    }

    [Fact]
    public void RestartService_ProceedsWhenServiceAlreadyStopped()
    {
        var runner = Substitute.For<IProcessRunner>();

        // Stop returns 1062 (already stopped)
        runner.Run("sc", Arg.Is<string>(a => a.Contains("stop")))
            .Returns((1062, "The service has not been started."));

        // Start succeeds
        runner.Run("sc", Arg.Is<string>(a => a.Contains("start")))
            .Returns((0, ""));

        var controller = new WindowsServiceController(runner);
        var result = controller.RestartService("TestService");

        Assert.True(result);

        // Query should not have been called since already stopped
        runner.DidNotReceive().Run("sc", Arg.Is<string>(a => a.Contains("query")));
        runner.Received().Run("sc", Arg.Is<string>(a => a.Contains("start")));
    }

    [Fact]
    public void RestartService_ReturnsFalseWhenServiceNeverReachesStopped()
    {
        var runner = Substitute.For<IProcessRunner>();

        // Stop succeeds (pending)
        runner.Run("sc", Arg.Is<string>(a => a.Contains("stop")))
            .Returns((0, ""));

        // Query always returns STOP_PENDING — never STOPPED
        runner.Run("sc", Arg.Is<string>(a => a.Contains("query")))
            .Returns((0, "STATE : 3  STOP_PENDING"));

        var controller = new WindowsServiceController(runner);
        var result = controller.RestartService("TestService");

        Assert.False(result);

        // Start should never be called since service didn't reach STOPPED
        runner.DidNotReceive().Run("sc", Arg.Is<string>(a => a.Contains("start")));
    }

    [Fact]
    public void IServiceController_CanBeMocked()
    {
        var mock = Substitute.For<IServiceController>();
        mock.ServiceExists("MyService").Returns(true);
        mock.RestartService("MyService").Returns(true);

        Assert.True(mock.ServiceExists("MyService"));
        Assert.True(mock.RestartService("MyService"));
    }
}
