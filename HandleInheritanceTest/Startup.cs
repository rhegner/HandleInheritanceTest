﻿using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace HandleInheritanceTest
{
	public class Startup
	{
		public void ConfigureServices(IServiceCollection services)
		{ }

		public void Configure(IApplicationBuilder app, IHostingEnvironment env)
		{
			app.Run(async (context) => await context.Response.WriteAsync("Hello World!"));
		}
	}
}
