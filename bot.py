
# COMMANDS:
#   !auth <member1> <member2> ...  
#       adds members to secure group ("authorize")
#   !noauth <member1> <member2> ...
#       "not authorized" = removes members from secure group
#   !post <msg>
#       msg is deleted and its ciphertext posted to the channel
#   !read
#       dms the plaintext of the last message posted if in authorized group
#   !members
#       shows current auth group

import discord
from discord.ext import commands
import json, os
from ca import issue_cert, revoke_cert, get_members
from crypto import encrypt_message, decrypt_message, load_cert, load_private_key

# SETTINGS

TOKEN = "INSERT BOT TOKEN HERE"
POSTS_FILE = "data/posts.json"
GROUPS_FILE = "data/groups.json"

intents = discord.Intents.default()
intents.message_content = True
intents.members = True          # needed to manage Discord roles
bot = commands.Bot(command_prefix="!", intents=intents)

# groups.json
# Structure:
# {
#   "alice": ["bob", "charlie"],
#   "bob":   ["alice", "bob"]
# }
# in the [] = who is allowed to decrypt the person's posts

def load_groups():
    if not os.path.exists(GROUPS_FILE):
        return {}
    with open(GROUPS_FILE) as f:
        return json.load(f)

def save_groups(groups):
    os.makedirs("data", exist_ok=True)
    with open(GROUPS_FILE, "w") as f:
        json.dump(groups, f, indent=2)

def get_user_group(username):
    # returns list of people authorized to read user's posts
    groups = load_groups()
    return groups.get(username, [])

def update_user_group(username, members):
    # overwrites the authorized list for user
    groups = load_groups()
    groups[username] = members
    save_groups(groups)

#posts.json
def load_posts():
    if not os.path.exists(POSTS_FILE):
        return []
    with open(POSTS_FILE) as f:
        return json.load(f)

def save_post(post):
    posts = load_posts()
    posts.append(post)
    os.makedirs("data", exist_ok=True)
    with open(POSTS_FILE, "w") as f:
        json.dump(posts, f, indent=2)

def get_latest_post():
    posts = load_posts()
    if not posts:
        return None
    return posts[-1]

# used by !auth and !noauth, kind of the "frontend" of the secure group, to visualize who's in the group
async def get_or_create_role(guild, role_name):
    # check role exists
    role = discord.utils.get(guild.roles, name=role_name)
    if not role:
        # create if not
        role = await guild.create_role(name=role_name)
    return role

async def rm_role(guild, role_name, username):
    role = discord.utils.get(guild.roles, name=role_name)
    if role:
        await role.delete()
    groups = load_groups()
    if username in groups:
        del groups[username]
        save_groups(groups)


# add members to authorized group
@bot.command()
async def auth(ctx, *members):
    username = str(ctx.author.name)
    role_name = f"{username}-secure"

    role = await get_or_create_role(ctx.guild, role_name)
    current_group = get_user_group(username)
    modif_counter = 0

    if username not in current_group :
        current_group.append(username)
        modif_counter += 1
        await ctx.author.add_roles(role)

    for member_name in members:
        # check person is registered (has a cert)
        if not os.path.exists(f"data/certs/{member_name}/cert.pem"):
            await ctx.send(f"{member_name} is not a valid username, skipping.")
            continue

        # add to groups.json if not already there
        if member_name not in current_group:
            current_group.append(member_name)
            modif_counter += 1

        # add to role
        for member_obj in ctx.guild.members:
            if member_obj.name == member_name:
                await member_obj.add_roles(role)

    # save (overwrite) updated group
    update_user_group(username, current_group)
    if modif_counter == 0 :
        await ctx.send(f"Nothing to update. {username}'s secure group : {current_group}")
    else :
        await ctx.send(f"Group updated. {username}'s secure group: {current_group}")

# remove members from secure group
@bot.command()
async def noauth(ctx, *members):
    username = str(ctx.author.name)
    role_name = f"{username}-secure"
    role = discord.utils.get(ctx.guild.roles, name=role_name)
    current_group = get_user_group(username)
    modif = 0

    for member_name in members:
        if member_name in current_group:
            current_group.remove(member_name)
            modif += 1

        for member_obj in ctx.guild.members:
            if member_obj.name == member_name:
                await member_obj.remove_roles(role)

    update_user_group(username, current_group)
    if modif == 0 :
        await ctx.send(f"Nothing to update.")
    else :
        await ctx.send(f"Group updated. {username}'s secure group: {current_group}")

# encrypt and post the message that was sent :
@bot.command()
async def post(ctx, *, message):
    await ctx.message.delete()
    username = str(ctx.author.name)
    if not os.path.exists(f"data/certs/{username}/cert.pem"): #should never happen
        await ctx.author.send("Not registered.")
        return
    # check who's authorized to read user's posts
    group = get_user_group(username)
    if not group:
        await ctx.author.send("Your secure group is empty. Use !auth to add members first.")
        return
    # load each authorized member's certificate
    member_certs = {}
    for member in group:
        cert_path = f"data/certs/{member}/cert.pem"
        if os.path.exists(cert_path):
            member_certs[member] = load_cert(cert_path)

    encrypted = encrypt_message(message, member_certs)
    save_post({"author": username, "data": encrypted})
    await ctx.send(f"[ENCRYPTED by {username}] {encrypted['ciphertext'][:60]}...")
    pass

# decrypts latest post and dm it to user (if user is authorized)
@bot.command()
async def read(ctx):
    await ctx.message.delete()
    username = str(ctx.author.name)
    key_path = f"data/certs/{username}/key.pem"
    if not os.path.exists(key_path):
        await ctx.author.send("You are not registered. Use !register first.")
        return

    if ctx.message.reference:
        replied_msg = await ctx.channel.fetch_message(ctx.message.reference.message_id)
        posts = load_posts()
        post = None
        for p in posts:
            if p['data']['ciphertext'][:60] in replied_msg.content:
                post = p
                break
        if not post:
            await ctx.author.send("Could not match that message to a stored post.")
            return
    else:       
        post = get_latest_post()
        if not post:
            await ctx.author.send("No posts yet.")
            return

    private_key = load_private_key(key_path)
    plaintext = decrypt_message(post["data"], username, private_key)
    if plaintext is not None :
        if username == post['author'] :
            await ctx.author.send(f" You said : {plaintext}")
        else :
            await ctx.author.send(f"{post['author']} said: {plaintext}")
    else :
        await ctx.author.send("you are not authorized to read this message.")

# shows current secure group
@bot.command()
async def members(ctx):
    username = str(ctx.author.name)
    group = get_user_group(username)
    if group:
        await ctx.send(f"{username}'s secure group: {', '.join(group)}")
    else:
        await ctx.send(f"{username} has no secure group yet. Use !auth to add members.")

#when connecting, issues a certificate to everyone that doesn't have one yet, deletes all the data of people who left
@bot.event
async def on_ready():
    await bot.wait_until_ready()
    print(f"Bot is online as {bot.user}")
    channel = bot.get_channel("INSERT CHANNEL ID HERE")
    await channel.send("Missed me ? I'm backkk")
    
    for guild in bot.guilds:
        curr_members = [str(member.name) for member in guild.members]
        for username in get_members() :
            if username not in curr_members:
                role_name = f"{username}-secure"
                revoke_cert(username)
                await rm_role(guild, role_name, username)
                print(f"Certificate revoked for {username}")
                print(f"{role_name} deleted")
                await channel.send(f"{username} left while i was not looking :'( Certificate revoked and role {role_name} deleted")            

    for guild in bot.guilds:
        for member in guild.members:
            username = str(member.name)

            role_name = f"{username}-secure"
            role = await get_or_create_role(member.guild, role_name)
            current_group = get_user_group(username)
            for membs in current_group :
                if membs not in guild.members :
                    current_group.remove(membs)
                    update_user_group(username, current_group)
            if username not in current_group :
                current_group.append(username)
                await member.add_roles(role)
                update_user_group(username, current_group)
            
            if not os.path.exists(f"data/certs/{username}/cert.pem"):
                issue_cert(username)
                print(f"Issued certificate to existing member: {username}")
                await channel.send(f"A certificate was just created for you {username} coz you're beautiful :>")

# creates cert for anyone new, upon joining, deletes all data from people leaving
@bot.event
async def on_member_join(member):
    channel = bot.get_channel("INSERT CHANNEL ID HERE")
    username = str(member.name)

    role_name = f"{username}-secure"
    role = await get_or_create_role(member.guild, role_name)
    current_group = get_user_group(username)
    current_group.append(username)
    await member.add_roles(role)
    update_user_group(username, current_group)

    issue_cert(username)
    print(f"Certificate issued for {username}")
    print(f"Secure group created for {username}")
    await channel.send(f"Certificate issued and secure group created for new member {username} !!")
    
@bot.event
async def on_member_remove(member):
    channel = bot.get_channel("INSERT CHANNEL ID HERE")
    username = str(member.name)
    role_name = f"{username}-secure"

    for m in member.guild.members:
        memb = str(m.name)

        current_group = get_user_group(memb)
        for membs in current_group :
            if membs is username :
                current_group.remove(membs)
                update_user_group(memb, current_group)

    revoke_cert(username)
    await rm_role(member.guild, role_name, username)
    print(f"Certificate revoked for {username}")
    print(f"{role_name} deleted")
    await channel.send(f"{username} just left :'( Certificate revoked and role {role_name} deleted")



bot.run(TOKEN)