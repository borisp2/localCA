namespace LocalCA.Core;

/// <summary>
/// Abstraction for OS firewall rule management.
/// </summary>
public interface IFirewallManager
{
    /// <summary>
    /// Create an inbound TCP allow rule for the specified port.
    /// Returns true if the rule was created successfully.
    /// </summary>
    bool AddInboundRule(string ruleName, int port);

    /// <summary>
    /// Remove an inbound rule by name.
    /// Returns true if the rule was found and removed.
    /// </summary>
    bool RemoveInboundRule(string ruleName);

    /// <summary>
    /// Check whether an inbound rule with the given name exists.
    /// </summary>
    bool RuleExists(string ruleName);
}
