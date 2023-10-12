using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Identity.Migrations
{
    /// <inheritdoc />
    public partial class SeedRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "1e8431b0-2ac3-4eb1-a0f6-639ccde65e57", "1", "Admin", "Admin" },
                    { "2f06a705-ece2-49a4-85ed-44f62e9d1105", "2", "Customer", "Customer" },
                    { "97ce2828-7ac1-4f4c-be49-b2100934ba88", "3", "User", "User" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "1e8431b0-2ac3-4eb1-a0f6-639ccde65e57");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "2f06a705-ece2-49a4-85ed-44f62e9d1105");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "97ce2828-7ac1-4f4c-be49-b2100934ba88");
        }
    }
}
