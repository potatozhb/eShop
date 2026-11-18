using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.API.Data.Migrations
{
    /// <inheritdoc />
    public partial class SharedPushedAuthorizationRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PushedAuthorizationRequests",
                columns: table => new
                {
                    ReferenceValueHash = table.Column<string>(type: "text", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Parameters = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PushedAuthorizationRequests", x => x.ReferenceValueHash);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PushedAuthorizationRequests");
        }
    }
}
