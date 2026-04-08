using NSubstitute;

namespace LocalCA.Core.Tests;

public class WindowsFirewallManagerTests
{
    [Fact]
    public void AddInboundRule_CallsNetshWithCorrectArguments()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run(Arg.Any<string>(), Arg.Any<string>())
            .Returns((0, "Ok."));

        var fw = new WindowsFirewallManager(runner);
        var result = fw.AddInboundRule("TestApp HTTPS", 443);

        Assert.True(result);
        runner.Received(1).Run(
            "netsh",
            Arg.Is<string>(a =>
                a.Contains("add rule") &&
                a.Contains("name=\"TestApp HTTPS\"") &&
                a.Contains("localport=443") &&
                a.Contains("dir=in") &&
                a.Contains("action=allow") &&
                a.Contains("protocol=TCP")));
    }

    [Fact]
    public void AddInboundRule_ReturnsFalseOnNonZeroExit()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run(Arg.Any<string>(), Arg.Any<string>())
            .Returns((1, "Error"));

        var fw = new WindowsFirewallManager(runner);
        Assert.False(fw.AddInboundRule("TestApp HTTPS", 443));
    }

    [Fact]
    public void RemoveInboundRule_CallsNetshDelete()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run(Arg.Any<string>(), Arg.Any<string>())
            .Returns((0, "Ok."));

        var fw = new WindowsFirewallManager(runner);
        var result = fw.RemoveInboundRule("TestApp HTTPS");

        Assert.True(result);
        runner.Received(1).Run(
            "netsh",
            Arg.Is<string>(a =>
                a.Contains("delete rule") &&
                a.Contains("name=\"TestApp HTTPS\"")));
    }

    [Fact]
    public void RemoveInboundRule_ReturnsFalseWhenRuleNotFound()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run(Arg.Any<string>(), Arg.Any<string>())
            .Returns((1, "No rules match the specified criteria."));

        var fw = new WindowsFirewallManager(runner);
        Assert.False(fw.RemoveInboundRule("NonExistent"));
    }

    [Fact]
    public void RuleExists_ReturnsTrueWhenNetshSucceeds()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run(Arg.Any<string>(), Arg.Any<string>())
            .Returns((0, "Rule Name: TestApp HTTPS"));

        var fw = new WindowsFirewallManager(runner);
        Assert.True(fw.RuleExists("TestApp HTTPS"));
    }

    [Fact]
    public void RuleExists_ReturnsFalseWhenNetshFails()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run(Arg.Any<string>(), Arg.Any<string>())
            .Returns((1, "No rules match."));

        var fw = new WindowsFirewallManager(runner);
        Assert.False(fw.RuleExists("NonExistent"));
    }

    [Fact]
    public void AddInboundRule_UsesCorrectPort()
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run(Arg.Any<string>(), Arg.Any<string>())
            .Returns((0, "Ok."));

        var fw = new WindowsFirewallManager(runner);
        fw.AddInboundRule("Custom Rule", 5001);

        runner.Received(1).Run(
            "netsh",
            Arg.Is<string>(a => a.Contains("localport=5001")));
    }
}
