"""
Escape Room Core
"""
import random, sys, asyncio


def create_container_contents(*escape_room_objects):
    return {obj.name: obj for obj in escape_room_objects}


def listFormat(object_list):
    l = ["a " + object.name for object in object_list if object["visible"]]
    return ", ".join(l)


class EscapeRoomObject:
    def __init__(self, name, **attributes):
        self.name = name
        self.attributes = attributes
        self.triggers = []

    def do_trigger(self, *trigger_args):
        return [event for trigger in self.triggers for event in [trigger(self, *trigger_args)] if event]

    def __getitem__(self, object_attribute):
        return self.attributes.get(object_attribute, False)

    def __setitem__(self, object_attribute, value):
        self.attributes[object_attribute] = value

    def __repr__(self):
        return self.name


class EscapeRoomCommandHandler:
    def __init__(self, room, player, output=print):
        self.room = room
        self.player = player
        self.output = output

    def _run_triggers(self, object, *trigger_args):
        for event in object.do_trigger(*trigger_args):
            self.output(event)
    def _cmd_look(self, look_args):
        look_result = None
        if len(look_args) == 0:
            object = self.room
        else:
            object = self.room["container"].get(look_args[-1], self.player["container"].get(look_args[-1], None))

        if not object or not object["visible"]:
            look_result = "You don't see that here."
        elif object["container"] != False and look_args and "in" == look_args[0]:
            if not object["open"]:
                look_result = "You can't do that! It's closed!"
            else:
                look_result = "Inside the {} you see: {}".format(object.name, listFormat(object["container"].values()))
        else:
            self._run_triggers(object, "look")
            look_result = object.attributes.get("description", "You see nothing special")
        self.output(look_result)
    
    def _cmd_unlock(self, unlock_args):
        unlock_result = None
        dogobject = self.room["container"].get("dog", None)
        if len(unlock_args) == 0:
            unlock_result = "Unlock what?!"
        elif len(unlock_args) == 1:
            unlock_result = "Unlock {} with what?".format(unlock_args[0])

        else:
            object = self.room["container"].get(unlock_args[0], None)
            unlock = False

            if object.name == "door" and dogobject["awake"] and not dogobject["crazy"]:
                unlock_result = "The terrifying dog is guarding the door, you can not unlock the door when dog is awake!"
            elif not object or not object["visible"]:
                unlock_result = "You don't see that here."
            elif not object["keyed"] and not object["keypad"]:
                unlock_result = "You can't unlock that!"
            elif not object["locked"]:
                unlock_result = "It's already unlocked"

            elif object["keyed"]:
                unlocker = self.player["container"].get(unlock_args[-1], None)
                if not unlocker:
                    unlock_result = "You don't have a {}".format(unlock_args[-1])
                elif unlocker not in object["unlockers"]:
                    unlock_result = "you can not unlock {} with {}.".format(object.name,unlock_args[-1])
                else:
                    unlock = True

            elif object["keypad"]:
                # TODO: For later Exercise
                pass

            if unlock:
                unlock_result = "You hear a click! It worked!"
                object["locked"] = False
                self._run_triggers(object, "unlock", unlocker)
        self.output(unlock_result)

    def _cmd_open(self, open_args):
        """
        Let's demonstrate using some ands instead of ifs"
        """
        if len(open_args) == 0:
            return self.output("Open what?")
        object = self.room["container"].get(open_args[-1], None)
        dogobject = self.room["container"].get("dog", None)

        success_result = "You open the {}.".format(open_args[-1])
        open_result = (
            ((not object or not object["visible"]) and "You don't see that.") or
            ((object["open"]) and "It's already open!") or
            ((object["locked"]) and "It's locked") or
            ((not object["openable"]) and "You can't open that!") or
            success_result)
        if object.name == "door" and dogobject["awake"] and not dogobject["crazy"]:
            open_result =  "The terrifying dog is guarding the door, you can not open it when dog is awake!"
        if object.name == "curtain" and object["openable"] == False:
            self.output("You find youself locked. You have to decipher the codedlock!\nBased on Caesar cipher:"+"The ciphertext is BCDEFG. The plaintext is ABCDEF. \nPlease calculate the key."+"(for example you should type in:'input 0')"+"\nHurry up man, time is running out!")
        if open_result == success_result:
            object["open"] = True
            self._run_triggers(object, "open")
            if object.name == "curtain":
                open_result += " The room is bright. Now, you can look around."
        self.output(open_result)

    def _cmd_get(self, get_args):
        if len(get_args) == 0:
            get_result = "Get what?"
        elif self.player["container"].get(get_args[0], None) != None:
            get_result = "You already have that"
        else:
            if len(get_args) > 1:
                container = self.room["container"].get(get_args[-1], None)
            else:
                container = self.room
            object = container["container"] and container["container"].get(get_args[0], None) or None

            success_result = "You got it"
            get_result = (
                ((not container or container["container"] == False) and "You can't get something out of that!") or
                ((container["openable"] and not container["open"]) and "It's not open.") or
                ((not object or not object["visible"]) and "You don't see that") or
                ((not object["gettable"]) and "You can't get that.") or
                success_result)

            if get_result == success_result:
                container["container"].__delitem__(object.name)
                self.player["container"][object.name] = object
                self._run_triggers(object, "get", container)
        self.output(get_result)

    def _cmd_hit(self, hit_args):
        if not hit_args:
            return self.output("What do you want to hit?")
        target_name = hit_args[0]
        with_what_name = None
        if len(hit_args) != 1:
            with_what_name = hit_args[-1]

        target = self.room["container"].get(target_name, None)
        if not target or not target["visible"]:
            return self.output("You don't see a {} here.".format(target_name))
        if with_what_name:
            with_what = self.player["container"].get(with_what_name, None)
            if not with_what:
                return self.output("You don't have a {}".format(with_what_name))
        else:
            with_what = None

        if target_name == "dog":
            return self.output("You can't beat the dog, better not to try.")

        elif not target["hittable"]:
            return self.output("You can't hit that!")
        elif target_name == "myself":
            self.output("You hit yourself with the {}".format(with_what_name))
            #Bai add inception
            self._run_triggers(target, "hit", with_what)
        else:
            self.output("You hit the {} with the {}".format(target_name, with_what_name))
            self._run_triggers(target, "hit", with_what)

    def _cmd_ask(self, ask_arg):
        response_msg = ""
        if len(ask_arg) == 1:
            response_msg = "Ask conch about what?"
        elif len(ask_arg) > 1:
            hint_name = ask_arg[-1]
            if hint_name == "door":
                response_msg = "The door needs a key to open."
            elif hint_name == "windows":
                response_msg = "The window is so thin, which seems easy to break. Maybe try to use something to hit it?"
            elif hint_name == "dog":
                response_msg = "It looks so terrified, find some way to keep ot calm down."
            elif hint_name == "flute":
                response_msg = "Maybe you can try to play it, see what will happen!"
            elif hint_name == "flyingkey":
                response_msg = "Seriously?"
            elif hint_name == "chest":
                response_msg = "Seriously?"
            elif hint_name == "hammer":
                response_msg = "It has magical power, it can smash anything!"
        self.output(response_msg)

    def _cmd_inventory(self, inventory_args):
        """
        Use return statements to end function early
        """
        if len(inventory_args) != 0:
            self.output("What?!")
            return

        items = ", ".join(["a " + item for item in self.player["container"]])
        self._run_triggers(object, "inventory")
        self.output("You are carrying {}".format(items))

    def _cmd_play(self, play_args):
        if len(play_args) == 0:
            return self.output("Play what?")
        object = self.player["container"].get(play_args[-1], None)
        dog = self.room["container"].get("dog",None)
        if (not object or not object["visible"]):
            return self.output("You don't see a {} here.".format(object.name))
        elif (object.name != "flute"):
            return self.output("You can not play that.")
        else:
            self.output("You play the flute, a wried sound is made. The dog starts barking, the voice seems to make him very uncomfortable, he tries to rush out of the room, slamming into the door again and again, and eventually breaks the door lock, now the door seems to be open.")
            dog["crazy"] = True
            self._run_triggers(object, "play")
    def _cmd_input(self,decipher_args):
        if len(decipher_args)== 0:
            return self.output("Input what?")
        else:
            if ("B" in decipher_args) or ("b" in decipher_args) or ("1" in decipher_args):
                curtain = self.room["container"].get("curtain",None)
                curtain["openable"] = True
                return self.output("It worked!Now you can walk around,try some instructions like look,open,hit.Better look first")
            else:
                return self.output("Wrong key,try again")
    
    def command(self, command_string):

        # no command
        if command_string.strip == "":
            return self.output("")

        command_args = command_string.split(" ")
        function = "_cmd_" + command_args[0]

        # unknown command
        if not hasattr(self, function):
            return self.output("You don't know how to do that.")

        # execute command dynamically
        getattr(self, function)(command_args[1:])
        self._run_triggers(self.room, "_post_command_", *command_args)


def create_room_description(room,dog):
    room_data = {
        "mirror": room["container"]["mirror"].name,
        "clock_time": room["container"]["clock"]["time"],
        "interesting": ""
    }
    dog = dog
    for item in room["container"].values():
        if item["interesting"]:
            room_data["interesting"] += "\n\t" + short_description(item)
    if room_data["interesting"]:
        room_data["interesting"] = "\nIn the room you see:" + room_data["interesting"]
    if room["light"] and not dog["awake"]:
        description = """You are in a locked room. There is only one door
and it is locked. Above the door is a clock that reads {clock_time}.
Across from the door is a large {mirror}. Below the mirror is an old chest.
The room is old and musty and the floor is creaky and warped.{interesting}
Wow, look! There is an amazing conch shining! When you don't know what to do next,
maybe you can ask conch!""".format(**room_data)
    elif room["light"] and dog["awake"]:
        description = """You are in a locked room. There is only one door
and it is locked. Above the door is a clock that reads {clock_time}.
Across from the door is a large {mirror}. Below the mirror is an old chest. Besides the mirror is an old closet.The room is old and musty and the floor is creaky and warped.Also, there is a terrifying dog guarding the door, better keep away with it {interesting}.""".format(**room_data)
    else:
        description = "It's dark. You barely see anything......wait! There is a piece of light, it seems like a window"
    return description


def create_door_description(door):
    description = "The door is strong and highly secured."
    if door["locked"]: description += " The door is locked."
    return description

def create_window_description(window, room):
    description = "There is a very very very very THIN window, but it is covered by a closed curtain."
    '''if "hammer" in player["container"]:
        description = "Noooo! You are in the space! there is no air"'''
    return description

def create_mirror_description(mirror, room):
    description = "You look in the mirror and see yourself."
    if "hairpin" in room["container"]:
        description += ".. wait, there's a hairpin in your hair. Where did that come from?"
    return description


def create_chest_description(chest):
    description = "An old chest. It looks worn, but it's still sturdy."
    if chest["locked"]:
        description += " And it appears to be locked."
    elif chest["open"]:
        description += " The chest is open."
    return description

def create_closet_description(closet):
    description = "An old closet. It looks worn, but it's still sturdy."
    if closet["locked"]:
        description += " And it appears to be locked."
    elif closet["open"]:
        description += " The closet is open. There is a flute in it"
    return description

def create_dog_description(dog):
    description = "there is a terrifying dog sleeping near the door"
    if dog["crazy"]:
        description = "The dog is crazy"
    elif dog["awake"]:
        description = "The dog wakes up because of the sound, it looks terrifying, better keep away from it."
    
    return description

def create_flyingkey_description(flyingkey):
    description = "A golden flying key with silver wings shimmering in the light"
    description += " is currently resting on the " + flyingkey["location"]
    return description


def create_flyingkey_short_description(flyingkey):
    return "A flying key on the " + flyingkey["location"]


def advance_time(room, clock, dog):
    event = None
    clock["time"] = clock["time"] - 1
    if clock["time"] == 0:
        for object in room["container"].values():
            if object["alive"]:
                object["alive"] = False
        event = "Oh no! The clock reaches 0 and a deadly gas fills the room!"
    room["description"] = create_room_description(room,dog)
    return event


def flyingkey_hit_trigger(room, flyingkey, key, dog, output):
    if flyingkey["location"] == "ceiling":
        output("You can't reach it up there!")
    elif flyingkey["location"] == "floor":
        output("It's too low to hit.")
    else:
        flyingkey["flying"] = False
        del room["container"][flyingkey.name]
        room["container"][key.name] = key
        dog = dog
        dog["awake"] = True
        output(
            "The flying key falls off the wall. When it hits the ground, it's wings break off and you now see an ordinary key. But at the same time, the terrifying dog near the door wakes up because of the sound, better stay away from it")


def short_description(object):
    if not object["short_description"]: return "a " + object.name
    return object["short_description"]


class EscapeRoomGame:
    def __init__(self, command_handler_class=EscapeRoomCommandHandler, output=print):
        self.room, self.player = None, None
        self.output = output
        self.command_handler_class = command_handler_class
        self.command_handler = None
        self.agents = []
        self.status = "void"

    def create_game(self, cheat=False):
        clock = EscapeRoomObject("clock", visible=True, time=100)
        mirror = EscapeRoomObject("mirror", visible=False)
        hairpin = EscapeRoomObject("hairpin", visible=False, gettable=True)
        key = EscapeRoomObject("key", visible=False, gettable=True, interesting=True)
        door = EscapeRoomObject("door", visible=False, openable=True, open= False, locked=True)
        chest = EscapeRoomObject("chest", visible=False, openable=True, open=False, keyed=True, locked=True,
                                 unlockers=[hairpin])
        room = EscapeRoomObject("room", visible=True, light=False)

        player = EscapeRoomObject("player", visible=False, alive=True)
        hammer = EscapeRoomObject("hammer", visible=True, gettable=True)
        window = EscapeRoomObject("window", visible=True, hittable=True, smashers=[hammer])
        flute = EscapeRoomObject("flute", visible=True, gettable=True)
        flyingkey = EscapeRoomObject("flyingkey", visible=False, flying=True, hittable=False, smashers=[hammer],
                                     interesting=True, location="ceiling")
        dog = EscapeRoomObject("dog", visible=False, awake=False, hittable=True, crazy=False)
        closet = EscapeRoomObject("closet",visible = False, open = False, openable=True, keyed=True, locked=True, unlockers=[key])
        
        curtain = EscapeRoomObject("curtain", visible = True, open = False, openable = False)

        myself = EscapeRoomObject("myself", visible = True, hittable = True, smashable = [hammer])

        conch = EscapeRoomObject("conch", visible=False)

        # setup containers
        player["container"] = {}
        chest["container"] = create_container_contents(hammer)
        closet["container"] = create_container_contents(flute)
        room["container"] = create_container_contents(player, door, clock, mirror, hairpin, chest, flyingkey, curtain, closet, dog, window, myself, conch)

        # set initial descriptions (functions)
        door["description"] = create_door_description(door)
        mirror["description"] = create_mirror_description(mirror, room)
        chest["description"] = create_chest_description(chest)
        flyingkey["description"] = create_flyingkey_description(flyingkey)
        flyingkey["short_description"] = create_flyingkey_short_description(flyingkey)
        key["description"] = "a golden key, cruelly broken from its wings."
        dog["description"] = create_dog_description(dog)
        closet["description"] = create_closet_description(closet)
        # the room's description depends on other objects. so do it last
        room["description"] = create_room_description(room,dog)

        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and clock.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and mirror.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and key.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and door.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and chest.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and hammer.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and flyingkey.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and closet.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and dog.__setitem__("visible", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and room.__setitem__("light", True))
        curtain.triggers.append(lambda obj, cmd, *args: (cmd == "open") and room.__setitem__("description", create_room_description(room,dog)))

        #Yang Hit?
        window.triggers.append(lambda obj, cmd, *args: (cmd == "look") and window.__setitem__("description",
                                                                                              create_window_description(
                                                                                                  window, room)))
        window.triggers.append(lambda obj, cmd, *args: (cmd == "hit") and window.__setitem__("description",
                                                                                             create_window_description(
                                                                                                 window, room)))

        mirror.triggers.append(lambda obj, cmd, *args: (cmd == "look") and hairpin.__setitem__("visible", True))
        mirror.triggers.append(lambda obj, cmd, *args: (cmd == "look") and mirror.__setitem__("description",create_mirror_description(mirror, room)))
        closet.triggers.append(lambda obj, cmd, *args: (cmd == "look") and closet.__setitem__("description",create_closet_description(closet)))
        door.triggers.append(lambda obj, cmd, *args: (cmd == "look") and door.__setitem__("description",create_door_description(door)))
        dog.triggers.append(lambda obj, cmd, *args: (cmd == "look") and dog.__setitem__("description",create_dog_description(dog)))
        door.triggers.append(lambda obj, cmd, *args: (cmd == "unlock") and door.__setitem__("description",create_door_description(door)))
        door.triggers.append(lambda obj, cmd, *args: (cmd == "open") and room["container"].__delitem__(player.name))
        room.triggers.append(lambda obj, cmd, *args: (cmd == "_post_command_") and advance_time(room, clock, dog))
        flute.triggers.append((lambda obj, cmd, *args: (cmd == "play") and door.__setitem__("locked", False)))
        flyingkey.triggers.append((lambda obj, cmd, *args: (cmd == "hit" and args[0] in obj[
            "smashers"]) and flyingkey_hit_trigger(room, flyingkey, key, dog,self.output)))

        #Bai
        myself.triggers.append(lambda obj, cmd, *args: (cmd == "hit") and room["container"].__delitem__(player.name))

        conch.triggers.append(lambda obj, cmd, *args: (cmd == "ask"))

        # TODO, the chest needs some triggers. This is for a later exercise

        self.room, self.player = room, player
        self.command_handler = self.command_handler_class(room, player, self.output)
        self.agents.append(self.flyingkey_agent(flyingkey))
        self.status = "created"

    async def flyingkey_agent(self, flyingkey):
        random.seed(0)  # this should make everyone's random behave the same.
        await asyncio.sleep(5)  # sleep before starting the while loop
        while self.status == "playing" and flyingkey["flying"]:
            locations = ["ceiling", "floor", "wall"]
            locations.remove(flyingkey["location"])
            random.shuffle(locations)
            next_location = locations.pop(0)
            old_location = flyingkey["location"]
            flyingkey["location"] = next_location
            flyingkey["description"] = create_flyingkey_description(flyingkey)
            flyingkey["short_description"] = create_flyingkey_short_description(flyingkey)
            flyingkey["hittable"] = next_location == "wall"
            self.output("The {} flies from the {} to the {}".format(flyingkey.name, old_location, next_location))
            for event in self.room.do_trigger("_post_command_"):
                self.output(event)
            await asyncio.sleep(5)

    def start(self):
        self.status = "playing"
        self.output("Where are you? You find yourself locked by a codedlock in a room.\n"
                    +"Based on Caesar cipher:"+"The ciphertext is BCDEFG. The plaintext is ABCDEF. \nPlease calculate the key."+"(for example you should type in:'input 0')\n"+"Hurry up man, time is running out!"
                    + "Better escape the codedlock first")

    def command(self, command_string):
        if self.status == "void":
            self.output("The world doesn't exist yet!")
        elif self.status == "created":
            self.output("The game hasn't started yet!")
        elif self.status == "dead":
            self.output("You already died! Sorry!")
        elif self.status == "escaped":
            self.output("You already escaped! The game is over!")
        else:
            self.command_handler.command(command_string)
            if not self.player["alive"]:
                self.output("You died. Game over!")
                self.status = "dead"
            elif self.player.name not in self.room["container"]:
                self.status = "escaped"
                self.output("VICTORY! You escaped!")


def game_next_input(game):
    input = sys.stdin.readline().strip()
    game.command(input)
    if game.status != 'playing':
        asyncio.get_event_loop().stop()
    else:
        flush_output(">> ", end='')


def flush_output(*args, **kargs):
    print(*args, **kargs)
    sys.stdout.flush()


async def main(args):
    loop = asyncio.get_event_loop()
    game = EscapeRoomGame(output=flush_output)
    game.create_game(cheat=("--cheat" in args))
    game.start()
    flush_output(">> ", end='')
    loop.add_reader(sys.stdin, game_next_input, game)
    await asyncio.wait([asyncio.ensure_future(a) for a in game.agents])


if __name__ == "__main__":
    asyncio.ensure_future(main(sys.argv[1:]))
    asyncio.get_event_loop().run_forever()
