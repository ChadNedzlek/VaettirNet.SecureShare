namespace SecureShare.Tests;

public class Pizza : UnsealedSecretValue<PizzaName, PizzaToppings>
{
    public Pizza(Guid id, PizzaName attributes, PizzaToppings @protected) : base(id, attributes, @protected)
    {
    }
}

public class PizzaToppings
{
    public bool Pepperoni { get; set; }
    public string CheeseType { get; set; } = "None";
}

public class PizzaName
{
    public PizzaName(string name)
    {
        Name = name;
    }

    public string Name { get; }
}