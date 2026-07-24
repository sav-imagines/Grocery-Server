using System.Text;
using Grocery_Server.Models;
using Grocery_Server.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SwaggerThemes;

namespace Grocery_Server
{
    public enum RateLimiters
    {
        ReallySlow,
        Slow,
        Fast,
        ReallyFast,
    }

    public class Program
    {
        private static void Seed()
        {
            string dir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string userFilesPath = Path.Combine(dir, "User Files");

            // creating the user files directory
            // also creates the directory for the database
            Directory.CreateDirectory(userFilesPath);
            using GroceryDbContext db = new(
                new DbContextOptionsBuilder<GroceryDbContext>()
                    .UseLazyLoadingProxies()
                    .UseNpgsql(
                        $"Server = localhost; Port = 5432; Database = GroceryServerDatabase; Username=postgres; Password=postgres"
                    )
                    .Options
            );
            // make a file to apply the migrations to
            File.Create(Path.Combine(dir, "Database.db"));
            // apply migrations to create a database
            db.Database.Migrate();
        }

        public static void Main(string[] args)
        {
            if (args.Any(arg => arg.ToLower() == "seed"))
            {
                Seed();
            }

            WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            //builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme);

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
            builder.Services.AddDbContextPool<GroceryDbContext>(options =>
                options
                    .UseLazyLoadingProxies()
                    .UseNpgsql(
                        $"Server = localhost; Port = 5432; Database = GroceryServerDatabase; Username=postgres; Password=postgres"
                    )
            );

            builder
                .Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Bearer";
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = builder.Configuration["Jwt:Issuer"],
                        ValidAudience = builder.Configuration["Jwt:Issuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)
                        ),
                    };
                });

            builder
                .Services.AddIdentity<User, IdentityRole>()
                .AddEntityFrameworkStores<GroceryDbContext>()
                .AddUserStore<UserStore<User, IdentityRole, GroceryDbContext>>();

            builder.Services.AddTransient<JwtService>();
            builder.Services.AddSingleton<ImageStorageService>();
            builder.Services.AddTransient<CleanupService>();

            builder.Services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                options.AddFixedWindowLimiter(
                    policyName: nameof(RateLimiters.ReallySlow),
                    settings =>
                    {
                        settings.PermitLimit = 20;
                        settings.Window = TimeSpan.FromMinutes(30);
                    }
                );
            });

            builder.Services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                options.AddFixedWindowLimiter(
                    policyName: nameof(RateLimiters.Slow),
                    settings =>
                    {
                        settings.PermitLimit = 15;
                        settings.Window = TimeSpan.FromMinutes(10);
                    }
                );
            });

            builder.Services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                options.AddFixedWindowLimiter(
                    policyName: nameof(RateLimiters.Fast),
                    settings =>
                    {
                        settings.PermitLimit = 20;
                        settings.Window = TimeSpan.FromSeconds(10);
                    }
                );
            });

            builder.Services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                options.AddFixedWindowLimiter(
                    policyName: nameof(RateLimiters.ReallyFast),
                    settings =>
                    {
                        settings.PermitLimit = 20;
                        settings.Window = TimeSpan.FromSeconds(10);
                    }
                );
            });

            WebApplication app = builder.Build();
            //app.Services.GetService<CleanupService>().Schedule(CancellationToken.None);

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerThemes(Theme.UniversalDark);
                app.UseSwaggerUI();
            }

            //app.UseHttpsRedirection();
            app.UseRateLimiter();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
