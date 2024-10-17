using VaettirNet.Threading.Tasks;
using FluentAssertions;

namespace SecureShare.Tests;

public class CovariantTaskTests
{
    public class Base
    {
        public virtual ICovariantTask<object> Get()
        {
            return CovariantTask.FromResult(new object());
        }
    }
    
    public class Derived : Base
    {
        public override async ICovariantTask<List<int>> Get()
        {
            await Task.Yield();
            return [1,2,3];
        }
    }

    [Test]
    public async Task BaseOnly()
    {
        Base b = new Base();
        await Task.Yield();
        object res = await b.Get();
        await Task.Yield();
        res.GetType().Should().Be(typeof(object));
    }
    
    [Test]
    public async Task DerivedOnly()
    {
        Derived b = new Derived();
        await Task.Yield();
        List<int> res = await b.Get();
        await Task.Yield();
        res.GetType().Should().Be(typeof(List<int>));
    }
    
    [Test]
    public async Task Mismatched()
    {
        Base b = new Derived();
        await Task.Yield();
        object res = await b.Get();
        await Task.Yield();
        res.GetType().Should().Be(typeof(List<int>));
    }
}