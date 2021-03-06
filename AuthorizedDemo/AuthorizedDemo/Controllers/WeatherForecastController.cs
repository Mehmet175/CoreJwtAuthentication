using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizedDemo.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private IJWTAuthenticationManager _authenticationManager;

        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger,
             IJWTAuthenticationManager jwtAuthenticationManager)
        {
            _logger = logger;
            _authenticationManager = jwtAuthenticationManager;
        }

        [HttpGet]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authentication([FromBody] UserModel userModel)
        {
            var token = _authenticationManager.Authenticate(userModel.Username, userModel.Password);
            if(token == null)
            {
                return Unauthorized();
            }
            return Ok(token);
        }
    }
}
