import datetime
import requests
import sys


def send_users_get_request(user_id, token):
    try:
        json_data = requests.get(
            f'https://api.vk.com/method/users.get?user_ids={user_id}&fields=city, music, movies, quotes, last_seen,'
            f' counters&access_token={token}&v=5.107').json()
    except requests.ConnectionError as exception:
        print("Ошибка соединения.")
        sys.exit(1)
    return json_data


def send_friends_get_request(user_id, token):
    try:
        json_data = requests.get(
            f'https://api.vk.com/method/friends.get?user_ids={user_id}&fields=name,'
            f' counters&access_token={token}&v=5.107').json()
    except requests.ConnectionError as exception:
        print("Ошибка соединения.")
        sys.exit(1)
    return json_data


def add_info_about_friends(result, json_data):
    friends_list = json_data["response"]["items"]
    result += "Список друзей : "
    for friend in friends_list:
        result += str(friend["first_name"]) + " " + str(friend["last_name"]) + "\r\n\t\t"
    return result


def get_information(user_id, token):
    json_data = send_users_get_request(user_id, token)

    name_surname = json_data["response"][0]["first_name"] + " " + json_data["response"][0]["last_name"]
    last_seen = str(datetime.datetime.fromtimestamp(json_data["response"][0]["last_seen"]["time"]).strftime('%d-%m-%Y %H:%M:%S'))

    result = "Имя и фамилия: " + name_surname + "\n"
    result += "Был в сети: " + last_seen + "\n"
    result += "Город: " + json_data["response"][0]["city"]["title"] + "\n"
    result += "Количество друзей: " + str(json_data["response"][0]["counters"]["friends"]) + "\n"
    result += "Количество подписчиков: " + str(json_data["response"][0]["counters"]["followers"]) + "\n"
    result += "Любимая музыка: " + str(json_data["response"][0]['music']) + "\n"
    result += "Любимые фильмы: " + str(json_data["response"][0]['movies']) + "\n"
    result += "Цитаты на странице: " + str(json_data["response"][0]['quotes']) + "\n"

    json_data = send_friends_get_request(user_id, token)
    result = add_info_about_friends(result, json_data)

    return result


# Чтобы запустить программу нужно иметь свой токен, который нужно вставить в переменную token
# Инструкция по получению токена на сайте https://vkhost.github.io/
# Для запуска используйте следующую команду python vk_api_task.py <userId>
def main():
    token = ""
    user_id = sys.argv[1]
    print(get_information(user_id, token))


main()
